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
using System.Collections.Generic;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;

namespace de4dot.code.deobfuscators.CryptoObfuscator;

class MethodsDecrypter {
	static readonly string[] requiredFields = new[] {
		"System.Byte[]", "System.Collections.Generic.Dictionary`2<System.Int32,System.Int32>", "System.ModuleHandle"
	};

	static readonly string[] requiredLocals = new[] {
		"System.Delegate", "System.ModuleHandle", "System.Reflection.Emit.DynamicILInfo",
		"System.Reflection.Emit.DynamicMethod", "System.Reflection.FieldInfo", "System.Reflection.FieldInfo[]",
		"System.Reflection.MethodBase", "System.Reflection.MethodBody", "System.Type", "System.Type[]"
	};

	readonly List<TypeDef> delegateTypes = new();
	readonly ModuleDefMD module;
	MethodDef decrypterCctor;
	MethodDef decryptMethod;
	public MethodsDecrypter(ModuleDefMD module) => this.module = module;

	public TypeDef Type { get; private set; }

	public IEnumerable<TypeDef> DelegateTypes => delegateTypes;
	public EmbeddedResource Resource { get; private set; }

	public bool Detected => Type != null;

	public void Find() {
		foreach (var type in module.Types) {
			if (Check(type))
				break;
		}
	}

	bool Check(TypeDef type) {
		if (type.NestedTypes.Count != 1)
			return false;
		if (type.Fields.Count != 3)
			return false;
		if (!new FieldTypes(type).All(requiredFields))
			return false;

		var cctor = type.FindStaticConstructor();
		if (cctor == null)
			return false;
		var decryptMethodTmp = FindDecryptMethod(type);
		if (decryptMethodTmp == null)
			return false;

		decryptMethod = decryptMethodTmp;
		decrypterCctor = cctor;
		Type = type;
		return true;
	}

	static MethodDef FindDecryptMethod(TypeDef type) {
		foreach (var method in type.Methods) {
			if (!method.IsStatic || method.Body == null)
				continue;
			if (!new LocalTypes(method).All(requiredLocals))
				continue;
			if (!DotNetUtils.IsMethod(method, "System.Void", "(System.Int32,System.Int32,System.Int32)"))
				continue;

			return method;
		}

		return null;
	}

	public void Decrypt(ResourceDecrypter resourceDecrypter, ISimpleDeobfuscator simpleDeobfuscator) {
		if (decryptMethod == null)
			return;

		Resource = CoUtils.GetResource(module, decrypterCctor);
		if (Resource == null)
			return;
		byte[] decrypted = resourceDecrypter.Decrypt(Resource.CreateReader().AsStream());
		var reader = ByteArrayDataReaderFactory.CreateReader(decrypted);
		int numEncrypted = reader.ReadInt32();
		Logger.v("Restoring {0} encrypted methods", numEncrypted);
		Logger.Instance.Indent();
		for (int i = 0; i < numEncrypted; i++) {
			int delegateTypeToken = reader.ReadInt32();
			uint codeOffset = reader.ReadUInt32();
			uint origOffset = reader.Position;
			reader.Position = codeOffset;
			Decrypt(ref reader, delegateTypeToken, simpleDeobfuscator);
			reader.Position = origOffset;
		}

		Logger.Instance.DeIndent();
	}

	void Decrypt(ref DataReader reader, int delegateTypeToken, ISimpleDeobfuscator simpleDeobfuscator) {
		var delegateType = module.ResolveToken(delegateTypeToken) as TypeDef;
		if (delegateType == null)
			throw new ApplicationException("Couldn't find delegate type");

		if (!GetTokens(delegateType, out int delToken, out int encMethToken, out int encDeclToken))
			throw new ApplicationException("Could not find encrypted method tokens");
		if (delToken != delegateTypeToken)
			throw new ApplicationException("Invalid delegate type token");
		var encType = module.ResolveToken(encDeclToken) as ITypeDefOrRef;
		if (encType == null)
			throw new ApplicationException("Invalid declaring type token");
		var encMethod = module.ResolveToken(encMethToken) as MethodDef;
		if (encMethod == null)
			throw new ApplicationException("Invalid encrypted method token");

		var bodyReader = new MethodBodyReader(module, ref reader);
		bodyReader.Read(encMethod);
		bodyReader.RestoreMethod(encMethod);
		Logger.v("Restored method {0} ({1:X8}). Instrs:{2}, Locals:{3}, Exceptions:{4}",
			Utils.RemoveNewlines(encMethod.FullName),
			encMethod.MDToken.ToInt32(),
			encMethod.Body.Instructions.Count,
			encMethod.Body.Variables.Count,
			encMethod.Body.ExceptionHandlers.Count);
		delegateTypes.Add(delegateType);
		simpleDeobfuscator.MethodModified(encMethod);
	}

	bool GetTokens(TypeDef delegateType, out int delegateToken, out int encMethodToken, out int encDeclaringTypeToken) {
		delegateToken = 0;
		encMethodToken = 0;
		encDeclaringTypeToken = 0;

		var cctor = delegateType.FindStaticConstructor();
		if (cctor == null)
			return false;

		var instrs = cctor.Body.Instructions;
		for (int i = 0; i < instrs.Count - 3; i++) {
			var ldci4_1 = instrs[i];
			if (!ldci4_1.IsLdcI4())
				continue;
			var ldci4_2 = instrs[i + 1];
			if (!ldci4_2.IsLdcI4())
				continue;
			var ldci4_3 = instrs[i + 2];
			if (!ldci4_3.IsLdcI4())
				continue;
			var call = instrs[i + 3];
			if (call.OpCode.Code != Code.Call)
				continue;
			var calledMethod = call.Operand as MethodDef;
			if (calledMethod == null)
				continue;
			if (calledMethod != decryptMethod)
				continue;

			delegateToken = ldci4_1.GetLdcI4Value();
			encMethodToken = ldci4_2.GetLdcI4Value();
			encDeclaringTypeToken = ldci4_3.GetLdcI4Value();
			return true;
		}

		return false;
	}
}
