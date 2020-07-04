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
