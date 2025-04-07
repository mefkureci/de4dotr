/*
    Copyright (C) 2011-2015 de4dot@gmail.com

    This file is part of de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    de4dot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with de4dot.  If not, see <http://www.gnu.org/licenses/>.
*/

using System.Text;
using de4dot.blocks;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.Xenocode;

class StringDecrypter {
	const int STRING_DECRYPTER_KEY_CONST = 1789;
	readonly ModuleDefMD module;
	public StringDecrypter(ModuleDefMD module) => this.module = module;

	public bool Detected => Method != null;
	public TypeDef Type { get; private set; }

	public MethodDef Method { get; private set; }

	public void Find() {
		foreach (var type in module.Types) {
			if (type.HasFields)
				continue;
			if (type.Methods.Count < 1 || type.Methods.Count > 3)
				continue;
			if (type.HasProperties || type.HasEvents)
				continue;

			MethodDef method = null;
			foreach (var m in type.Methods) {
				if (m.Name == ".ctor" || m.Name == ".cctor")
					continue;
				if (DotNetUtils.IsMethod(m, "System.String", "(System.String,System.Int32)")) {
					method = m;
					continue;
				}

				method = null;
				break;
			}

			if (method == null || method.Body == null)
				continue;

			bool foundConstant = false;
			foreach (var instr in method.Body.Instructions) {
				if (instr.IsLdcI4() && instr.GetLdcI4Value() == STRING_DECRYPTER_KEY_CONST) {
					foundConstant = true;
					break;
				}
			}

			if (!foundConstant)
				continue;

			Type = type;
			Method = method;
			break;
		}
	}

	public string Decrypt(string es, int magic) {
		int newLen = es.Length / 4;
		var sb = new StringBuilder(newLen);
		for (int i = 0; i < newLen * 4; i += 4) {
			char c = (char)(es[i] - 'a' +
				((es[i + 1] - 'a') << 4) +
				((es[i + 2] - 'a') << 8) +
				((es[i + 3] - 'a') << 12) - magic);
			magic += STRING_DECRYPTER_KEY_CONST;
			sb.Append(c);
		}

		return sb.ToString();
	}
}
