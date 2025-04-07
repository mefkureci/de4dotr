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

using System;
using System.Text;
using de4dot.blocks;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.CryptoObfuscator;

class StringDecrypter {
	readonly ModuleDefMD module;
	byte[] decryptedData;
	public StringDecrypter(ModuleDefMD module) => this.module = module;

	public bool Detected => Type != null;
	public TypeDef Type { get; private set; }

	public MethodDef Method { get; private set; }

	public EmbeddedResource Resource { get; private set; }

	public void Find() {
		if (!FindStringDecrypterType(out var type, out var method))
			return;

		Type = type;
		Method = method;
	}

	public void Initialize(ResourceDecrypter resourceDecrypter) {
		if (decryptedData != null || Type == null)
			return;

		string resourceName = GetResourceName();
		Resource = DotNetUtils.GetResource(module, resourceName) as EmbeddedResource;
		if (Resource == null)
			return;
		Logger.v("Adding string decrypter. Resource: {0}", Utils.ToCsharpString(Resource.Name));

		decryptedData = resourceDecrypter.Decrypt(Resource.CreateReader().AsStream());
	}

	string GetResourceName() {
		string defaultName = module.Assembly.Name.String + module.Assembly.Name.String;

		var cctor = Type.FindStaticConstructor();
		if (cctor == null)
			return defaultName;

		foreach (string s in DotNetUtils.GetCodeStrings(cctor)) {
			if (DotNetUtils.GetResource(module, s) != null)
				return s;
			try {
				return Encoding.UTF8.GetString(Convert.FromBase64String(s));
			}
			catch {
				string s2 = CoUtils.DecryptResourceName(module, cctor);
				try {
					return Encoding.UTF8.GetString(Convert.FromBase64String(s2));
				}
				catch {
				}
			}
		}

		return defaultName;
	}

	public string Decrypt(int index) {
		int len = DeobUtils.ReadVariableLengthInt32(decryptedData, ref index);
		return Encoding.Unicode.GetString(decryptedData, index, len);
	}

	bool FindStringDecrypterType(out TypeDef theType, out MethodDef theMethod) {
		theType = null;
		theMethod = null;

		foreach (var type in module.Types) {
			if (type.IsPublic)
				continue;
			if (!type.HasFields)
				continue;
			if (type.Fields.Count > 2)
				continue;
			if (DotNetUtils.FindFieldType(type, "System.Byte[]", true) == null)
				continue;
			if (type.Methods.Count != 2 && type.Methods.Count != 3)
				continue;
			if (type.NestedTypes.Count > 0)
				continue;

			MethodDef method = null;
			foreach (var m in type.Methods) {
				if (m.Name == ".ctor" || m.Name == ".cctor")
					continue;
				if (DotNetUtils.IsMethod(m, "System.String", "(System.Int32)")) {
					method = m;
					continue;
				}

				break;
			}

			if (method == null)
				continue;

			theType = type;
			theMethod = method;
			return true;
		}

		return false;
	}
}
