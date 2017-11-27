# Master Password in Go
This is an implemtation of the password system described at
http://masterpasswordapp.com/

There is a module if you want to use the algorithm in your own code,
and an app if you want a command line tool.

## Module

To use simply

```
import github.com/afterecho/masterpassword/masterpassword
```

## App

To use run

```
go get github.com/afterecho/masterpassword/gompw
```

and use the tool `gompw`

NOTE that this version does not contain all of the password types that
the official mpw tool implements. However the ones that is does generate
are identical to the ones from the official tool.

## License


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
