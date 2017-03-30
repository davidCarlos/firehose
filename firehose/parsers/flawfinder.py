#!/usr/bin/env python

#   Copyright 2017 David Carlos  <ddavidcarlos1392@gmail.com>
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#   USA

import sys
import re
from firehose.model import Message, Function, Point, \
    File, Location, Generator, Metadata, Analysis, Issue, Notes, Failure, \
    CustomFields
import xml.etree.cElementTree as ET


def main():
    """ Main entry to flawfinder parser """
    arg_file = sys.argv[1]
    report = load_file(arg_file)
    analysis = parse_file(report)
    analysis.to_xml().write('flawfinder.firehose.xml')


def load_file(arg_file):
    """TODO: Docstring for load_file.

    :arg1: file passed by cli
    :returns: file loaded in memory
    """
    try:
        return open(arg_file, 'r')
    except Exception as e:
        raise e


def parse_file(loaded_file):
    """ Parser loaded flawfinder output

    :loaded_file: flawfinder report, loaded in memory
    :returns: Analysis object, representing the final xml.

    """

    generator = Generator(name='flawfinder',
                          version='1.31')
    metadata = Metadata(generator, None, None, None)
    analysis = Analysis(metadata, [])

    pattern = "\([a-z]*\)"
    prog = re.compile(pattern)

    line = loaded_file.readline()

    location_nodes = list()
    weakness_paths = []
    weakness_lines = []
    weakness_messages = []
    weakness_cwes = []
    while line:
        if prog.search(line) and prog.search(line).group(0) != "()":
            cwe = ""
            weakness_paths.append(line.split(":")[0])
            weakness_lines.append(line.split(":")[1])

            message_line = loaded_file.readline()
            message = ""
            while not prog.search(message_line) and message_line != "\n":
                message += " " + message_line
                line_cwe = get_cwe(message_line)
                if line_cwe:
                    cwe = line_cwe
                message_line = loaded_file.readline()
            weakness_messages.append(message)
            # TODO: Flawfinder can returns more than one CWE,
            # when this rappends, get_cwe cannot return a valid value
            # Fix this.

            if cwe != "":
                weakness_cwes.append(cwe)
            else:
                weakness_cwes.append(0)
        line = loaded_file.readline()

    counter = 0
    for weakness in weakness_paths:
        location = Location(file=File(weakness, None),
                            function=None,
                            point=Point(int(weakness_lines[counter]), 0))

        issue = Issue(int(weakness_cwes[counter]), None, location,
                      Message(text=weakness_messages[counter]),notes=None,
                      trace=None, severity=None, customfields=None)

        analysis.results.append(issue)
        counter += 1

    return analysis

def get_cwe(line):
    """TODO: Docstring for _get_cwe.
    :returns: TODO

    """
    pattern = "\([A-Z]*\-([1-9]*)\)"
    prog = re.compile(pattern)
    if prog.search(line):
        return prog.search(line).group(1)

if __name__ == '__main__':
    main()
