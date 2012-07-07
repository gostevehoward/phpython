#!/usr/bin/env python

import ast
import contextlib
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
    def __init__(self, node_type, subnodes):
        self.type = node_type
        self.subnodes = subnodes

    def accept(self, visitor):
        return visitor.visit_node(self)

class Array(object):
    def __init__(self, elements):
        self.elements = elements

    def accept(self, visitor):
        return visitor.visit_array(self.elements)

class Scalar(object):
    def __init__(self, value):
        self.value = value

    def accept(self, visitor):
        return visitor.visit_scalar(self.value)

def remove_namespace(tag):
    return tag.rpartition('}')[2]

def read_thing(element):
    if element.tag.startswith(NS_NODE):
        return read_node(element)
    elif element.tag.startswith(NS_SCALAR):
        return read_scalar(element)
    else:
        raise ValueError('Do not know how to read %r' % element.tag)

def read_node(element):
    assert element.tag.startswith(NS_NODE)
    subnodes = {}
    for child in element:
        if child.tag.startswith(NS_SUBNODE):
            assert len(child) == 1, child
            tag  = remove_namespace(child.tag)
            body = read_thing(child[0])
            subnodes[tag] = body
        elif child.tag.startswith(NS_ATTRIBUTE):
            pass # ignore "attributes"
        else:
            raise ValueError('Do not know how to read %r within node' % child.tag)
    return Node(remove_namespace(element.tag), subnodes)

def read_scalar(element):
    assert element.tag.startswith(NS_SCALAR)
    tag = remove_namespace(element.tag)
    if tag == 'array':
        return Array([read_thing(child) for child in element])
    elif tag == 'string':
        return Scalar(element.text)
    elif tag == 'true':
        return Scalar(True)
    elif tag == 'false':
        return Scalar(False)
    elif tag == 'int':
        return Scalar(int(element.text))
    elif tag == 'null':
        return Scalar(None)
    else:
        raise ValueError('Unknown scalar type %r' % tag)

def parse_php(stream):
    process = subprocess.Popen(
        ['php', PARSE_PHP_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    xml, stderr = process.communicate(stream.read())
    xml_root = ElementTree.fromstring(xml)

    assert xml_root.tag == 'AST'
    assert len(xml_root) == 1
    statements = xml_root[0]
    assert statements.tag == NS_SCALAR + 'array'

    return read_thing(statements)

class PrettyFormatter(object):
    def __init__(self):
        self._indent_level = 0
        self._accumulator = []

    def pretty_format(self, thing):
        self._accumulator = []
        thing.accept(self)
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

    def visit_node(self, node):
        self._print(node.type + ' {\n')
        with self._indent(2):
            for key, value in node.subnodes.iteritems():
                self._print(key + ': ')
                value.accept(self)
                self._print(',\n')
        self._print('}')

    def visit_array(self, elements):
        if not elements:
            self._print('[]')
        elif len(elements) == 1:
            self._print('[')
            elements[0].accept(self)
            self._print(']')
        else:
            self._print('[\n')
            with self._indent(2):
                for element in elements:
                    element.accept(self)
                    self._print(',\n')
            self._print(']')

    def visit_scalar(self, value):
        self._print(repr(value))

class Translator(object):
    def translate(self, thing):
        return thing.accept(self)

    def _parse_arguments(self, arg_nodes):
        arguments = []
        for arg_node in arg_nodes.elements:
            assert not arg_node.subnodes['byRef'].value
            value = self.translate(arg_node.subnodes['value'])
            arguments.append(value)
        return arguments

    def _parse_call(self, node, name_tag):
        callable_name = self._parse_name(node.subnodes[name_tag])
        return ast.Call(
            func=ast.Name(id=callable_name, ctx=ast.Load),
            args=self._parse_arguments(node.subnodes['args']),
            keywords=[],
            starargs=None,
            kwargs=None,
        )

    def _parse_name(self, name_node):
        return '.'.join(scalar.value for scalar in name_node.subnodes['parts'].elements)

    def visit_node(self, node):
        if node.type == 'Expr_Include':
            include_string = node.subnodes['expr'].subnodes['value'].value
            return ast.Import(names=[ast.alias(name=include_string, asname=None)])
        elif node.type == 'Expr_Assign':
            variable_name = node.subnodes['var'].subnodes['name'].value
            value = self.translate(node.subnodes['expr'])
            return ast.Assign(targets=[ast.Name(id=variable_name, ctx=ast.Store)], value=value)
        elif node.type == 'Expr_New':
            return self._parse_call(node, 'class')
        elif node.type == 'Expr_FuncCall':
            return self._parse_call(node, 'name')
        elif node.type.startswith('Scalar_'):
            return node.subnodes['value'].accept(self)
        elif node.type == 'Stmt_TryCatch':
            body = [self.translate(child) for child in node.subnodes['stmts'].elements]
            except_handlers = []
            for catch_node in node.subnodes['catches'].elements:
                except_handlers.append(
                    ast.ExceptHandler(
                        type=ast.Str(self._parse_name(catch_node.subnodes['type'])),
                        name=ast.Str(catch_node.subnodes['var'].value),
                        body=[
                            self.translate(child)
                            for child in catch_node.subnodes['stmts'].elements
                        ],
                    ),
                )
            return ast.TryExcept(body=body, handlers=except_handlers, orelse=[])
        elif node.type == 'Expr_MethodCall':
            target = node.subnodes['var'].subnodes['name'].value
            name = node.subnodes['name'].value
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id=target, ctx=ast.Load),
                    attr=name,
                    ctx=ast.Load,
                ),
                args=self._parse_arguments(node.subnodes['args']),
                keywords=[],
                starargs=None,
                kwargs=None,
            )
        elif node.type == 'Expr_Concat':
            return ast.BinOp(
                left=self.translate(node.subnodes['left']),
                op=ast.Add(),
                right=self.translate(node.subnodes['right']),
            )
        elif node.type == 'Expr_Exit':
            return ast.Expr(value=ast.Str('exit!'))
        elif node.type == 'Expr_Variable':
            return ast.Name(id=node.subnodes['name'].value, ctx=ast.Load)
        elif node.type == 'Stmt_Echo':
            return ast.Print(
                dest=None,
                values=[self.translate(child) for child in node.subnodes['exprs'].elements],
                nl=True,
            )
        else:
            #raise ValueError("don't know how to handle %r" % node.type)
            print "don't know how to handle %r" % node.type
            return ast.Expr(value=ast.Str('unknown %s' % node.type))

    def visit_array(self, elements):
        return ast.List(elts=[self.translate(element) for element in elements], ctx=ast.Load)

    def visit_scalar(self, value):
        if isinstance(value, basestring):
            return ast.Str(value)
        elif isinstance(value, (bool, types.NoneType)):
            return ast.Name(id=repr(value), ctx=ast.Load)
        elif isinstance(value, int):
            return ast.Num(value)
        else:
            return ast.Str('unknown scalar %r' % value)

def main():
    with open(sys.argv[1]) as stream:
        statements = parse_php(stream)

    formatter = PrettyFormatter()
    print formatter.pretty_format(statements)
    print '----'

    translator = Translator()
    statements = [translator.translate(statement) for statement in statements.elements]
    module = ast.Module(body=statements)
    print ast.dump(module)
    print '----'
    unparse.Unparser(module)
    print

if __name__ == '__main__':
    main()
