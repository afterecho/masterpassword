// Copyright 2017 Darren Gibb
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package masterpassword

import (
	"testing"
)

func TestGetPasswordTypeMap(t *testing.T) {
	pwtypes := []struct {
		lettercode string
		numtemplates int
	}{
		{"x", 2},
		{"l", 21},
		{"m", 2},
		{"s", 1},
		{"b", 3},
		{"i", 1},
		{"n", 1},
		{"p", 3}}

	typemap := GetPasswordTypeMap()

	if len(typemap) != len(pwtypes) {
		t.Error("Unexpected number of password types\n")
	}

	for _, ty := range pwtypes {
		if pwt, ok := typemap[ty.lettercode]; ok {
			if len(pwt.maps) != ty.numtemplates {
				t.Errorf("Mismatched number of templates. Expected %d, got %d\n", ty.numtemplates, len(pwt.maps))
			}
		} else {
			t.Errorf("Passwordtype %s missing\n", ty.lettercode)
		}
	}
}

func TestPassword(t *testing.T) {
	cases := []struct {
		sitecounter int
		username, sitename, passwordtype, masterpw, want string
	}{
		// Values below obtained from original mpw command line util with
		// for i in x l m s b i n p; do P=$(pwgen 16 1); U=$(pwgen 8 1), S=$(pwgen 16 1); C=$(jot -r 1); F=$(echo -n $P | mpw -qqq -f n -u $U -m 0 -t $i -c $C $S); echo '{'$C', "'$U'", "'$S'", "'$i'", "'$P'", "'$F'"},'; done
		{13, "pahK5xi7,", "ojohbejahy7Eohei", "x", "roxacheedaphahH2", "b2'fw)fK#&f3JF7SMg8L"},
		{11, "IeS1ohch,", "fiex2phooGhaeR0e", "l", "chahc7maengohX9u", "Luco5%FalzKoju"},
		{25, "juighaB5,", "kaNeiw4aiw1waeDi", "m", "Roihiy7Phah4choo", "RogDup7#"},
		{64, "am8ePh4i,", "iuWeiK7ieY4AefoD", "s", "Eir5hi9eishu8Oos", "Cey8"},
		{90, "eit3Ohda,", "theiboaloot1aiKe", "b", "Eechai6oofiX4Eor", "NbT2zXJ9"},
		{20, "Wieph2oo,", "die0ooj3chiGhiaX", "i", "quaJu8aeTh7vienu", "0931"},
		{95, "eiY7ohfo,", "oj9Pae7nisohShe9", "n", "ie5IeweiYafohthi", "kiklawogu"},
		{56, "phoo0Wae,", "Ieb9soree2oPheic", "p", "Eighai3Iepehah1a", "je cibte zaf saqefdi"}}
	for _, c := range cases {
		got, _ := Password(c.username, c.sitename, c.sitecounter, c.passwordtype, []byte(c.masterpw))
		if got != c.want {
			t.Errorf("Password(%q, %q, %d, %q, %q) == %q, want %q", c.username, c.sitename, c.sitecounter, c.passwordtype, c.masterpw, got, c.want)
		}
	}
}
