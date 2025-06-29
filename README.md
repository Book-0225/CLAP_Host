# CLAP Host ホストアプリケーション

本アプリケーションは、プロセス間通信（IPC）を行い、CLAPプラグインをロードしてオーディオデータを処理する「ホスト」として機能します。  
本アプリケーションを利用すると様々なアプリケーションと連動して他のアプリケーションからCLAPプラグインを用いることが可能になります

## 注意事項

無保証です。自己責任で使用してください。  
このアプリケーションを利用したことによる、いかなる損害・トラブルについても責任を負いません。

## 使用方法

### 実行方法

コマンドプロンプトまたは他のプログラムから、本実行可能ファイル```CLAPHost.exe```を起動します。その際、必要に応じて後述のコマンドライン引数を指定します。

```CLAPHost.exe [引数]```

### 引数

本アプリケーションは、動作をカスタマイズするためのコマンドライン引数に対応しています。

- -uid [ID]
  このホストインスタンスを識別するための一意な64ビット整数IDを指定します。IPCオブジェクト名の一部として使用されます。
  デフォルト値: 実行時のプロセスID

- -pipe [ベース名]
  コマンド送受信に使用する名前付きパイプのベース名を指定します。'\\.\pipe\' プレフィックスを含めてください。
  デフォルト値: '\\.\pipe\ClapBridge'

- -shm <ベース名>
  オーディオデータ交換に使用する共有メモリのベース名を指定します。
  デフォルト値: 'Local\ClapSharedAudio'

- -event_ready [ベース名]
  クライアント（呼び出し元）がオーディオデータを準備完了したことを通知するイベントのベース名を指定します。
  デフォルト値: 'Local\ClapClientReady'

- -event_done [ベース名]
  ホスト（本アプリ）がオーディオ処理を完了したことを通知するイベントのベース名を指定します。
  デフォルト値: 'Local\CLAPHostDone'

**注意:**
[ベース名] にスペースを含む場合は、名前全体をダブルクォーテーション (") で囲ってください。
IPCオブジェクトの最終的な名前は、指定された [ベース名] と -uid で指定されたIDをアンダースコア (_) で連結したものになります。
例: 'CLAPHost.exe -uid 12345' の場合、共有メモリ名は 'Local\ClapSharedAudio_12345' となります。

#### 使用例

- デフォルト設定で起動
```CLAPHost.exe```

- ユニークIDを '98765' に指定して起動
```CLAPHost.exe -uid 98765```

- すべてのIPC名をカスタム設定して起動
```CLAPHost.exe -uid 111 -pipe "\\.\pipe\MyPipe" -shm "Local\MyShm"```

## 機能

### IPCコマンド

ホストは名前付きパイプを通じて、以下のテキストベースのコマンドを受け付けます。コマンドは改行 (`\n`) で終了する必要があります。

- `load_and_set_state "[path]" [sample_rate] [block_size] [state_data]`  
    CLAPプラグインをロードし、続けて状態を復元します。これは、プラグインのロードと状態設定をアトミックに行うための**推奨コマンド**です。
  - `[path]`: CLAPプラグインファイル (`.clap`) へのフルパス。**必ずダブルクォーテーションで囲んでください。**
  - `[sample_rate]` (オプション): サンプルレート (double型)。
  - `[block_size]` (オプション): ブロックサイズ (int型)。
  - `[state_data]` (オプション): `get_state` で取得したBase64エンコード済みの状態データ。
  - **応答**: `OK\n`

- `get_state`
  現在ロードされているプラグインの状態（プリセットデータ）を取得します。
  - **応答**:
    - 成功時: `OK <base64_encoded_data>\n`
    - 状態が空、または取得に失敗した場合: `OK \n` (OKの後に空文字列)

- `show_gui`
  プラグインのGUIエディタウィンドウを表示します。
  - **応答**: `OK\n`

- `hide_gui`
  表示されているGUIエディタウィンドウを閉じます。
  - **応答**: `OK\n`

- `exit`
  ホストアプリケーションを安全に終了させます。
  - **応答**: `OK\n`

### 旧コマンド (後方互換性のために維持)

以下のコマンドも利用可能ですが、タイミングの問題を避けるために `load_and_set_state` の使用を推奨します。

- `load_plugin "[path]" [sample_rate] [block_size]`
  CLAPプラグインをロードします。
  - `[path]`: CLAPプラグインファイル (`.clap`) へのフルパス。**必ずダブルクォーテーションで囲んでください。**
  - `[sample_rate]` (オプション): サンプルレート (double型)。
  - `[block_size]` (オプション): ブロックサイズ (int型)。
  - **応答**: `OK\n`

### オーディオ処理

オーディオデータの処理は、共有メモリとイベントオブジェクトを介して行われます。処理フローは以下の通りです。

1. **クライアント**: 共有メモリに処理したいオーディオデータを書き込みます。
2. **クライアント**: `-event_ready` で指定されたイベントをシグナル状態にします。
3. **ホスト**: イベントを検知し、共有メモリからオーディオデータを読み込み、ロードされたCLAPプラグインで処理を実行します。
4. **ホスト**: 処理結果を共有メモリの出力領域に書き戻します。
5. **ホスト**: `-event_done` で指定されたイベントをシグナル状態にします。
6. **クライアント**: イベントを検知し、共有メモリから処理済みのオーディオデータを読み取ります。

共有メモリのレイアウトは以下の通りです。（各バッファの最大サイズは`2048`サンプルに固定されています）

1. `AudioSharedData` 構造体 (サンプルレート、サンプル数、チャンネル数)
2. 入力オーディオバッファ (Left)
3. 入力オーディオバッファ (Right)
4. 出力オーディオバッファ (Left)
5. 出力オーディオバッファ (Right)

## ビルド方法

### 前提条件

- Visual Studio 2022
- Git

開発者コマンドプロンプト上で

1. ```git clone --recursive https://github.com/Book-0225/CLAP_Host.git```
2. ```cd Clap_host```
3. ```msbuild /p:Configuration=Release /p:Platform="x64"```

上記の通り実行すると```x64/Release/CLAPHost.exe```が生成されるはずです。

## Credits

### CLAP

```
MIT License

Copyright (c) 2021 Alexandre BIQUE

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
