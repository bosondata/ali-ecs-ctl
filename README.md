# Yet Another Aliyun ECS Controller


## Build

```bash
$ cargo build --release
```

To build a statically linked binary, use the ``x86_64-unknown-linux-musl`` target:

```bash
$ cargo build --release --target=x86_64-unknown-linux-musl
```

## Usage

Define credentials as environment variable:

```bash
export ALIYUN_ACCESS_KEY_ID=<ALIYUN-ACCESS-KEY>
export ALIYUN_SECRET=<ALIYUN-SECRET>
```

### List instances

```bash
$ ali_ecs_ctl list
```

### Reboot instances

Reboot instances if ssh timeout:
```bash
$ ali_ecs_ctl reboot -c ssh
```

Reboot instances if ping timeout:
```bash
$ ali_ecs_ctl reboot -c ping
```

Reboot single instances by ip:
```bash
$ ali_ecs_ctl reboot --ip <instance_public_ip_address>
```


### Reboot ALL instances!

```bash
$ ali_ecs_ctl rebootall
```


## License

The MIT License (MIT)

Copyright (c) 2016 - 2017 BosonData

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.