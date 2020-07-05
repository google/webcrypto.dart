// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:flutter/material.dart';
import 'dart:async';
import 'dart:convert' show utf8;

import 'package:convert/convert.dart' show hex;
import 'package:webcrypto/webcrypto.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _output = '-';
  final _input = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('SHA-1 Hashing'),
        ),
        body: Container(
          padding: EdgeInsets.all(10),
          child: Column(
            children: [
              Text(
                'Compute SHA-1 hash of input below.\n\n'
                'Click the button to refresh the computed output.'
                'Output will be displayed in hexadecimal encoding.',
              ),
              Text(
                'input',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              _textEntry(),
              SizedBox(height: 50),
              Text(
                'output',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              Text('$_output'),
            ],
          ),
        ),
      ),
    );
  }

  Widget _textEntry() {
    return Row(
      children: <Widget>[
        Expanded(
          child: TextField(
            controller: _input,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
          ),
        ),
        IconButton(
          icon: Icon(Icons.autorenew),
          tooltip: 'compute hash',
          onPressed: _refreshHash,
        )
      ],
    );
  }

  Future<void> _refreshHash() async {
    final result = await Hash.sha1.digestBytes(utf8.encode(_input.text));
    setState(() {
      _output = hex.encode(result);
    });
  }
}
