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
import 'dart:convert' show utf8, base64Decode, jsonEncode;

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
  String _hash = '-';
  String _importedKey = '-';
  String _generatedKey = '-';
  final _inputPlain = TextEditingController();
  final _inputRawKey = TextEditingController(text: "3nle6RpFx77jwrksoNUb1Q==");

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Webcrypto'),
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
                'input plain text',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              _textEntryPlain(),
              SizedBox(height: 50),
              Text(
                'hash',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              Text('$_hash',
                key: Key('HashOutput'),
              ),
              Text(
                'Click the button to import the raw key.\n'
                'Output will be key in jwk form or an error message.',
              ),
              Text(
                'input raw key',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              _textEntryRawKey(),
              Text(
                'imported key',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              Text('$_importedKey',
                key: Key('KeyOutput'),
              ),
              Text(
                'generate AES key',
                textScaleFactor: 1.2,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              RaisedButton(
                key: Key("GenerateKey"),
                child: Text('GENERATE KEY'),
                onPressed: _generateKey,
              ),
              Text('$_generatedKey',
                key: Key('GenKeyOutput'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _textEntryPlain() {
    return Row(
      children: <Widget>[
        Expanded(
          child: TextField(
            controller: _inputPlain,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
          ),
        ),
        IconButton(
          key: Key('RefreshHash'),
          icon: Icon(Icons.autorenew),
          tooltip: 'compute hash',
          onPressed: _refreshHash,
        )
      ],
    );
  }

  Widget _textEntryRawKey() {
    return Row(
      children: <Widget>[
        Expanded(
          child: TextField(
            controller: _inputRawKey,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
          ),
        ),
        IconButton(
          key: Key('ImportRawKey'),
          icon: Icon(Icons.autorenew),
          tooltip: 'import key',
          onPressed: _importRawKey,
        )
      ],
    );
  }

  Future<void> _refreshHash() async {
    final result = await Hash.sha1.digestBytes(utf8.encode(_inputPlain.text));
    setState(() {
      _hash = hex.encode(result);
    });
  }

  Future<void> _importRawKey() async {
    final keyData = base64Decode(_inputRawKey.text);
    try {
      final key = await AesGcmSecretKey.importRawKey(keyData);
      final jwk = await key.exportJsonWebKey();
      setState(() {
        _importedKey = jsonEncode(jwk);
      });
    } catch (e, stack) {
      setState(() {
        _importedKey = "import failed: $e \n\n $stack";
      });
    }
  }

  Future<void> _generateKey() async {
    try {
      final key = await AesCbcSecretKey.generateKey(256);
      final jwk = await key.exportJsonWebKey();
      setState(() {
        _generatedKey = jsonEncode(jwk);
      });
    } catch (e, stack) {
      setState(() {
        _generatedKey = "generating key failed: $e \n\n $stack";
      });
    }
  }
}
