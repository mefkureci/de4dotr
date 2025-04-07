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

using System.IO;
using System.Security.Cryptography;
using System.Text;
using de4dot.blocks;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.Agile_NET;

class ResourceDecrypter {
	static readonly string[] requiredFields1 = new[] { "System.Reflection.Assembly", "System.String[]" };

	static readonly string[] requiredFields2 = new[] {
		"System.Reflection.Assembly", "System.String[]", "System.Collections.Hashtable"
	};

	readonly ModuleDefMD module;
	MethodDef rsrcResolveMethod;
	public ResourceDecrypter(ModuleDefMD module) => this.module = module;

	public ResourceDecrypter(ModuleDefMD module, ResourceDecrypter oldOne) {
		this.module = module;
		Type = Lookup(oldOne.Type, "Could not find rsrcType");
		RsrcRrrMethod = Lookup(oldOne.RsrcRrrMethod, "Could not find rsrcRrrMethod");
		rsrcResolveMethod = Lookup(oldOne.rsrcResolveMethod, "Could not find rsrcResolveMethod");
	}

	public bool Detected => Type != null;
	public TypeDef Type { get; private set; }

	public MethodDef RsrcRrrMethod { get; private set; }

	T Lookup<T>(T def, string errorMessage) where T : class, ICodedToken => DeobUtils.Lookup(module, def, errorMessage);
	public void Find() => FindResourceType();

	void FindResourceType() {
		var cctor = DotNetUtils.GetModuleTypeCctor(module);
		if (cctor == null)
			return;

		foreach (var calledMethod in DotNetUtils.GetCalledMethods(module, cctor)) {
			if (!calledMethod.IsStatic || calledMethod.Body == null)
				continue;
			if (!DotNetUtils.IsMethod(calledMethod, "System.Void", "()"))
				continue;
			var type = calledMethod.DeclaringType;
			var fieldTypes = new FieldTypes(type);
			if (!fieldTypes.Exactly(requiredFields1) &&
			    !fieldTypes.Exactly(requiredFields2))
				continue;

			var resolveHandler = DotNetUtils.GetMethod(type, "System.Reflection.Assembly",
				"(System.Object,System.ResolveEventArgs)");
			var decryptMethod = DotNetUtils.GetMethod(type, "System.Byte[]", "(System.IO.Stream)");
			if (resolveHandler == null || !resolveHandler.IsStatic)
				continue;
			if (decryptMethod == null || !decryptMethod.IsStatic)
				continue;

			Type = type;
			RsrcRrrMethod = calledMethod;
			rsrcResolveMethod = resolveHandler;
			return;
		}
	}

	public EmbeddedResource MergeResources() {
		if (rsrcResolveMethod == null)
			return null;
		var resource =
			DotNetUtils.GetResource(module, DotNetUtils.GetCodeStrings(rsrcResolveMethod)) as EmbeddedResource;
		if (resource == null)
			return null;
		DeobUtils.DecryptAndAddResources(module, resource.Name.String, () => DecryptResource(resource));
		return resource;
	}

	byte[] DecryptResource(EmbeddedResource resource) {
		var reader = resource.CreateReader();
		reader.Position = 0;
		string key = reader.ReadSerializedString();
		byte[] data = reader.ReadRemainingBytes();
		var cryptoTransform = new DESCryptoServiceProvider {
			Key = Encoding.ASCII.GetBytes(key), IV = Encoding.ASCII.GetBytes(key)
		}.CreateDecryptor();
		var memStream = new MemoryStream(data);
		using (var reader2 = new BinaryReader(new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Read))) {
			return reader2.ReadBytes((int)memStream.Length);
		}
	}
}
