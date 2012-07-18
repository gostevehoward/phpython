#!/usr/bin/env python

import ast
import contextlib
import itertools
import os
import pprint
import subprocess
import sys
import types
from xml.etree import ElementTree

import IPython

import unparse

PARSE_PHP_SCRIPT = os.path.join(os.getcwd(), 'parse.php')
NS_NODE = '{http://nikic.github.com/PHPParser/XML/node}'
NS_SUBNODE = '{http://nikic.github.com/PHPParser/XML/subNode}'
NS_ATTRIBUTE = '{http://nikic.github.com/PHPParser/XML/attribute}'
NS_SCALAR = '{http://nikic.github.com/PHPParser/XML/scalar}'

class Node(object):
    def __init__(self, node_type, subnode_map):
        self.type = node_type
        self._subnode_map = subnode_map

    def __getitem__(self, name):
        return self._subnode_map[name]

    def subnodes(self):
        return self._subnode_map.iteritems()

    def __repr__(self):
        return 'Node(%s)' % self.type

def remove_namespace(tag):
    return tag.rpartition('}')[2]

class XmlPhpParseTreeReader(object):
    def _read_element(self, element):
        if element.tag.startswith(NS_NODE):
            return self._read_node(element)
        elif element.tag.startswith(NS_SCALAR):
            return self._read_scalar(element)
        else:
            raise ValueError('Do not know how to read %r' % element.tag)

    def _read_node(self, element):
        assert element.tag.startswith(NS_NODE)
        subnode_map = {}
        for child in element:
            if child.tag.startswith(NS_SUBNODE):
                assert len(child) == 1, child
                tag  = remove_namespace(child.tag)
                body = self._read_element(child[0])
                subnode_map[tag] = body
            elif child.tag.startswith(NS_ATTRIBUTE):
                pass # ignore "attributes"
            else:
                raise ValueError('Do not know how to read %r within node' % child.tag)
        return Node(remove_namespace(element.tag), subnode_map)

    def _read_scalar(self, element):
        assert element.tag.startswith(NS_SCALAR)
        tag = remove_namespace(element.tag)
        if tag == 'array':
            return [self._read_element(child) for child in element]
        elif tag == 'string':
            return element.text
        elif tag == 'true':
            return True
        elif tag == 'false':
            return False
        elif tag == 'int':
            return int(element.text)
        elif tag == 'null':
            return None
        else:
            raise ValueError('Unknown scalar type %r' % tag)

    def parse_tree(self, xml_root):
        assert xml_root.tag == 'AST'
        assert len(xml_root) == 1
        statements = xml_root[0]
        assert statements.tag == NS_SCALAR + 'array'
        return self._read_element(statements)

    def parse_php(self, stream):
        process = subprocess.Popen(
            ['php', PARSE_PHP_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        xml, stderr = process.communicate(stream.read())
        xml_root = ElementTree.fromstring(xml)
        return self.parse_tree(xml_root)

class PrettyFormatter(object):
    def __init__(self):
        self._indent_level = 0
        self._accumulator = []

    def pretty_format(self, thing):
        self._accumulator = []
        self._do_format(thing)
        return ''.join(self._accumulator)

    @contextlib.contextmanager
    def _indent(self, amount):
        self._indent_level += amount
        yield
        self._indent_level -= amount

    def _print(self, string):
        if not self._accumulator or self._accumulator[-1].endswith('\n'):
            self._accumulator.append(' ' * self._indent_level)
        self._accumulator.append(string)

    def _do_format(self, thing):
        if isinstance(thing, Node):
            self._format_node(thing)
        elif isinstance(thing, list):
            self._format_list(thing)
        else:
            self._format_scalar(thing)

    def _format_node(self, node):
        self._print('%s (%s) {\n' % (node.type, ', '.join(name for name, value in node.subnodes())))
        with self._indent(2):
            for key, value in node.subnodes():
                self._print(key + ': ')
                self._do_format(value)
                self._print(',\n')
        self._print('}')

    def _format_list(self, elements):
        if not elements:
            self._print('[]')
        elif len(elements) == 1:
            self._print('[')
            self._do_format(elements[0])
            self._print(']')
        else:
            self._print('[\n')
            with self._indent(2):
                for element in elements:
                    self._do_format(element)
                    self._print(',\n')
            self._print(']')

    def _format_scalar(self, value):
        self._print(repr(value))

class Translator(object):
    def _name(self, name):
        if name == 'this':
            name = 'self'
        return ast.Name(id=name)

    def _build_lookup(self, name):
        assert name.type in ('Name', 'Name_FullyQualified')
        expression = self._name(name['parts'][0])
        for part in name['parts'][1:]:
            expression = ast.Attribute(value=expression, attr=part)
        return expression

    def _method_call(self, object_expression, function_name, args):
        return ast.Call(
            func=ast.Attribute(
                value=object_expression,
                attr=function_name,
            ),
            args=args,
            keywords=[],
            starargs=None,
            kwargs=None,
        )

    def translate_statements(self, statements):
        results = list(itertools.chain.from_iterable(
            self._translate_statement(statement) for statement in statements
        ))
        if results:
            return results
        else:
            return ast.Pass()

    def _translate_params(self, params, add_self=False):
        names, defaults = [], []
        if add_self:
            names.append(self._name('self'))
            defaults.append(None)
        for param in params:
            assert not param['byRef']
            names.append(self._name(param['name']))
            defaults.append(
                self._translate_expression(param['default']) if param['default'] else None
            )
        return ast.arguments(args=names, vararg=None, kwarg=None, defaults=defaults)

    def _translate_statement(self, node):
        if node.type == 'Stmt_Namespace':
            # TODO: assert on node['name']['parts']
            for statement in self.translate_statements(node['stmts']):
                yield statement
        elif node.type == 'Expr_Include':
            include_string = node['expr']['value']
            yield ast.Import(names=[ast.alias(name=include_string, asname=None)])
        elif node.type == 'Expr_Assign':
            target = self._translate_expression(node['var'])
            value = self._translate_expression(node['expr'])
            yield ast.Assign(targets=[target], value=value)
        elif node.type == 'Stmt_TryCatch':
            body = self.translate_statements(node['stmts'])
            except_handlers = []
            for catch_node in node['catches']:
                except_handlers.append(
                    ast.ExceptHandler(
                        type=self._build_lookup(catch_node['type']),
                        name=self._name(catch_node['var']),
                        body=self.translate_statements(catch_node['stmts']),
                    ),
                )
            yield ast.TryExcept(body=body, handlers=except_handlers, orelse=[])
        elif node.type == 'Expr_Exit':
            yield ast.Expr(self._method_call(self._name('sys'), 'exit', []))
        elif node.type == 'Stmt_Use':
            yield ast.Expr(ast.Str('Ignoring use: %s' % '.'.join(node['uses'][0]['name']['parts'])))
        elif node.type == 'Stmt_Echo':
            yield ast.Print(
                dest=None,
                values=[self._translate_expression(child) for child in node['exprs']],
                nl=True,
            )
        elif node.type == 'Stmt_Class':
            bases = [self._build_lookup(node['extends'])] if node['extends'] else []
            bases.extend([self._build_lookup(child) for child in node['implements']])
            if not bases:
                bases = [self._name('object')]
            name = node['name']
            assert node['type'] == 0
            yield ast.ClassDef(
                name=node['name'],
                bases=bases,
                body=self.translate_statements(node['stmts']),
                decorator_list=[],
            )
        elif node.type == 'Stmt_Property':
            #assert node['type'] == 2 TODO
            for child in node['props']:
                value = (
                    self._translate_expression(child['default'])
                    if child['default']
                    else self._name('None')
                )
                yield ast.Assign(targets=[self._name(child['name'])], value=value)
        elif node.type == 'Stmt_ClassMethod':
            assert not node['byRef']
            #assert node['type'] == 2 TODO
            yield ast.FunctionDef(
                name=node['name'],
                args=self._translate_params(node['params'], add_self=True),
                body=self.translate_statements(node['stmts']),
                decorator_list=[],
            )
        elif node.type == 'Stmt_Return':
            yield ast.Return(value=self._translate_expression(node['expr']))
        elif node.type == 'Stmt_If':
            else_body = []
            for if_node in node['elseifs']:
                assert False # TODO
            if node['else']:
                assert node['else'].type == 'Stmt_Else'
                else_body.extend(self.translate_statements(node['else']['stmts']))
            yield ast.If(
                test=self._translate_expression(node['cond']),
                body=self.translate_statements(node['stmts']),
                orelse=else_body,
            )
        elif node.type == 'Stmt_Foreach':
            assert not node['byRef']
            value_expression = self._translate_expression(node['valueVar'])
            if node['keyVar']:
                target = ast.Tuple(elts=[
                    self._translate_expression(node['keyVar']),
                    value_expression,
                ])
            else:
                target = value_expression
            yield ast.For(
                target=target,
                iter=self._translate_expression(node['expr']),
                body=self.translate_statements(node['stmts']),
                orelse=[],
            )
        elif node.type == 'Stmt_Break':
            if node['num']: # TODO
                print 'WARNING: break with number!'
            yield ast.Break()
        else:
            yield ast.Expr(self._translate_expression(node))

    def _parse_arguments(self, arg_nodes):
        arguments = []
        for arg_node in arg_nodes:
            assert not arg_node['byRef']
            value = self._translate_expression(arg_node['value'])
            arguments.append(value)
        return arguments

    def _parse_call(self, node, name_tag):
        callable_expression = self._build_lookup(node[name_tag])
        return ast.Call(
            func=callable_expression,
            args=self._parse_arguments(node['args']),
            keywords=[],
            starargs=None,
            kwargs=None,
        )

    def _translate_expression(self, node):
        if node.type == 'Expr_New':
            return self._parse_call(node, 'class')
        elif node.type == 'Expr_FuncCall':
            return self._parse_call(node, 'name')
        elif node.type.startswith('Scalar_'):
            return self._translate_scalar(node)
        elif node.type == 'Expr_MethodCall':
            target = self._translate_expression(node['var'])
            name = node['name']
            return self._method_call(target, name, self._parse_arguments(node['args']))
        elif node.type == 'Expr_Concat':
            return ast.BinOp(
                left=self._translate_expression(node['left']),
                op=ast.Add(),
                right=self._translate_expression(node['right']),
            )
        elif node.type == 'Expr_Variable':
            return self._name(node['name'])
        elif node.type == 'Expr_PropertyFetch':
            return ast.Attribute(value=self._translate_expression(node['var']), attr=node['name'])
        elif node.type == 'Expr_StaticCall':
            return self._method_call(
                self._build_lookup(node['class']),
                node['name'],
                self._parse_arguments(node['args']),
            )
        elif node.type == 'Expr_NotIdentical':
            return ast.Compare(
                left=self._translate_expression(node['left']),
                ops=[ast.NotEq()],
                comparators=[self._translate_expression(node['right'])],
            )
        elif node.type == 'Expr_Array':
            keys, values = [], []
            for item in node['items']:
                assert not item['byRef']
                keys.append(self._translate_expression(item['key']))
                values.append(self._translate_expression(item['value']))
            if any(keys):
                return ast.Dict(keys=keys, values=values)
            else:
                return ast.List(elts=values)
        elif node.type == 'Expr_ArrayDimFetch':
            if node['dim']:
                index = ast.Index(value=self._translate_expression(node['dim']))
            else:
                index = ast.Index(value=ast.Num(-1)) # TODO
            return ast.Subscript(
                value=self._translate_expression(node['var']),
                slice=index,
            )
        elif node.type == 'Expr_ConstFetch':
            return self._build_lookup(node['name'])
        elif node.type == 'Expr_ClassConstFetch':
            return ast.Attribute(
                value=self._build_lookup(node['class']),
                attr=node['name'],
            )
        elif node.type == 'Expr_Ternary':
            test = self._translate_expression(node['cond'])
            if node['if']:
                body = self._translate_expression(node['if'])
            else:
                body = test
            return ast.IfExp(test=test, body=body, orelse=self._translate_expression(node['else']))
        elif node.type == 'Expr_Equal':
            return ast.Compare(
                left=self._translate_expression(node['left']),
                ops=[ast.Eq()],
                comparators=[self._translate_expression(node['right'])],
            )
        else:
            #raise ValueError("don't know how to handle %r" % node.type)
            print "don't know how to handle %r" % node.type
            return ast.Str('unknown %r' % node.type)

    def _translate_scalar(self, node):
        if node.type == 'Scalar_String':
            return ast.Str(node['value'])
        elif node.type == 'Scalar_Bool':
            return self._name('True' if node['value'] else 'False')
        elif node.type == 'Scalar_Null':
            self.self._name('None')
        elif node.type == 'Scalar_LNumber':
            return ast.Num(node['value'])
        elif node.type == 'Scalar_Encapsed':
            sum_ast = None
            for part in node['parts']:
                if isinstance(part, Node):
                    expression = self._translate_expression(part)
                elif isinstance(part, basestring):
                    expression = ast.Str(part)
                else:
                    raise ValueError('Unexpected part in Scalar_Encapsed: %r' % part)

                if sum_ast is None:
                    sum_ast = expression
                else:
                    sum_ast = ast.BinOp(left=sum_ast, op=ast.Add(), right=expression)
            return sum_ast
        else:
            print "don't know how to handle %r" % node.type
            return ast.Str('unknown scalar %r' % node.type)

def main():
    parser = XmlPhpParseTreeReader()
    with open(sys.argv[1]) as stream:
        statements = parser.parse_php(stream)

    formatter = PrettyFormatter()
    print formatter.pretty_format(statements)
    print '----'

    translator = Translator()
    translated_statements = translator.translate_statements(statements)
    module = ast.Module(body=translated_statements)
    print ast.dump(module)
    print '----'
    unparse.Unparser(module)
    print

if __name__ == '__main__':
    main()
