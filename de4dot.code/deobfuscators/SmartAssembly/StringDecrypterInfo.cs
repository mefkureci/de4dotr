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
using System.Globalization;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.SmartAssembly;

enum StringDecrypterVersion {
	V1,
	V2,
	V3,
	V4,
	V5,
	Unknown
}

class StringDecrypterInfo {
	static readonly string[] fields2x = new[] { "System.IO.Stream", "System.Int32" };

	static readonly string[] fields3x = new[] { "System.Byte[]", "System.Int32" };

	readonly ModuleDefMD module;
	ResourceDecrypter resourceDecrypter;

	public StringDecrypterInfo(ModuleDefMD module, TypeDef stringsEncodingClass) {
		this.module = module;
		this.StringsEncodingClass = stringsEncodingClass;
	}

	public StringDecrypterVersion DecrypterVersion { get; private set; }

	public TypeDef GetStringDelegate { get; set; }
	public TypeDef StringsType { get; set; }
	public MethodDef CreateStringDelegateMethod { get; set; }
	public TypeDef StringsEncodingClass { get; }

	public bool CanDecrypt => resourceDecrypter == null || resourceDecrypter.CanDecrypt;
	public MethodDef SimpleZipTypeMethod { get; private set; }

	public EmbeddedResource StringsResource { get; private set; }

	public int StringOffset { get; private set; }

	public int XorValue { get; private set; }

	public bool StringsEncrypted => SimpleZipTypeMethod != null;
	public MethodDef StringDecrypterMethod { get; private set; }

	StringDecrypterVersion GuessVersion(MethodDef cctor) {
		var fieldTypes = new FieldTypes(StringsEncodingClass);
		if (fieldTypes.Exactly(fields2x))
			return StringDecrypterVersion.V2;
		if (cctor == null)
			return StringDecrypterVersion.V1;
		if (fieldTypes.Exactly(fields3x))
			return StringDecrypterVersion.V3;
		return StringDecrypterVersion.Unknown;
	}

	public bool Initialize(IDeobfuscator deob, ISimpleDeobfuscator simpleDeobfuscator) {
		var cctor = StringsEncodingClass.FindStaticConstructor();
		if (cctor != null)
			simpleDeobfuscator.Deobfuscate(cctor);

		DecrypterVersion = GuessVersion(cctor);

		if (!FindDecrypterMethod())
			throw new ApplicationException("Could not find string decrypter method");

		if (!FindStringsResource(deob, simpleDeobfuscator, cctor))
			return false;

		if (DecrypterVersion <= StringDecrypterVersion.V3) {
			MethodDef initMethod;
			if (DecrypterVersion == StringDecrypterVersion.V3)
				initMethod = cctor;
			else if (DecrypterVersion == StringDecrypterVersion.V2)
				initMethod = StringDecrypterMethod;
			else
				initMethod = StringDecrypterMethod;

			StringOffset = 0;
			if (DecrypterVersion != StringDecrypterVersion.V1) {
				if (CallsGetPublicKeyToken(initMethod)) {
					var pkt = PublicKeyBase.ToPublicKeyToken(module.Assembly.PublicKeyToken);
					if (!PublicKeyBase.IsNullOrEmpty2(pkt)) {
						for (int i = 0; i < pkt.Data.Length - 1; i += 2)
							StringOffset ^= (pkt.Data[i] << 8) + pkt.Data[i + 1];
					}
				}

				if (DeobUtils.HasInteger(initMethod, 0xFFFFFF) &&
				    DeobUtils.HasInteger(initMethod, 0xFFFF)) {
					StringOffset ^= ((StringDecrypterMethod.MDToken.ToInt32() & 0xFFFFFF) - 1) % 0xFFFF;
				}
			}
		}
		else {
			int? offsetVal = FindOffsetValue(cctor);
			if (offsetVal == null)
				throw new ApplicationException("Could not find string offset");
			StringOffset = offsetVal.Value;

			int? xorVal = FindXorValue(StringDecrypterMethod, StringsEncodingClass.HasNestedTypes, simpleDeobfuscator);
			if (xorVal != null) {
				DecrypterVersion = StringDecrypterVersion.V5;
				XorValue = (int)xorVal;
			}
			else
				DecrypterVersion = StringDecrypterVersion.V4;
		}

		SimpleZipTypeMethod = FindSimpleZipTypeMethod(cctor) ?? FindSimpleZipTypeMethod(StringDecrypterMethod);
		if (SimpleZipTypeMethod != null)
			resourceDecrypter =
				new ResourceDecrypter(new ResourceDecrypterInfo(module, SimpleZipTypeMethod, simpleDeobfuscator));

		return true;
	}

	bool CallsGetPublicKeyToken(MethodDef method) {
		foreach (var calledMethod in DotNetUtils.GetMethodCalls(method)) {
			if (calledMethod.ToString() == "System.Byte[] System.Reflection.AssemblyName::GetPublicKeyToken()")
				return true;
		}

		return false;
	}

	bool FindStringsResource(IDeobfuscator deob, ISimpleDeobfuscator simpleDeobfuscator, MethodDef cctor) {
		if (StringsResource != null)
			return true;

		if (DecrypterVersion <= StringDecrypterVersion.V3) {
			StringsResource =
				DotNetUtils.GetResource(module, (module.Mvid ?? Guid.NewGuid()).ToString("B")) as EmbeddedResource;
			if (StringsResource != null)
				return true;
		}

		if (FindStringsResource2(deob, simpleDeobfuscator, cctor))
			return true;
		if (FindStringsResource2(deob, simpleDeobfuscator, StringDecrypterMethod))
			return true;

		return false;
	}

	bool FindStringsResource2(IDeobfuscator deob, ISimpleDeobfuscator simpleDeobfuscator, MethodDef initMethod) {
		if (initMethod == null)
			return false;

		StringsResource = FindStringResource(initMethod);
		if (StringsResource != null)
			return true;

		simpleDeobfuscator.DecryptStrings(initMethod, deob);
		StringsResource = FindStringResource(initMethod);
		if (StringsResource != null)
			return true;

		return false;
	}

	public byte[] Decrypt() {
		if (!CanDecrypt)
			throw new ApplicationException("Can't decrypt strings");
		return resourceDecrypter.Decrypt(StringsResource);
	}

	// Find the embedded resource where all the strings are encrypted
	EmbeddedResource FindStringResource(MethodDef method) {
		foreach (string s in DotNetUtils.GetCodeStrings(method)) {
			if (s == null)
				continue;
			if (DotNetUtils.GetResource(module, s) is EmbeddedResource resource)
				return resource;
		}

		return null;
	}

	// Find the string decrypter string offset value or null if none found
	int? FindOffsetValue(MethodDef method) {
		var fieldDict = new FieldDefAndDeclaringTypeDict<IField>();
		foreach (var field in method.DeclaringType.Fields)
			fieldDict.Add(field, field);

		var offsetField = FindOffsetField(method);
		if (offsetField == null)
			return null;

		return FindOffsetValue(method, (FieldDef)fieldDict.Find(offsetField), fieldDict);
	}

	// Find the string decrypter xor value or null if none found
	int? FindXorValue(MethodDef method, bool hasNested, ISimpleDeobfuscator simpleDeobfuscator) {
		if (hasNested) {
			var calls = DotNetUtils.GetMethodCalls(method);
			foreach (var call in calls) {
				if (DotNetUtils.IsMethod(method, "System.String", "(System.Int32)")) {
					method = call as MethodDef;
					break;
				}
			}
		}

		simpleDeobfuscator.Deobfuscate(method);

		if (method == null || method.Body == null)
			return null;
		var instructions = method.Body.Instructions;
		for (int i = 0; i < instructions.Count; i++) {
			var ldci4 = instructions[i];
			if (ldci4.OpCode != OpCodes.Ldc_I4)
				continue;
			var xor = instructions[i + 1];
			if (xor.OpCode != OpCodes.Xor)
				continue;

			return ldci4.GetLdcI4Value();
		}

		return null;
	}

	IField FindOffsetField(MethodDef method) {
		var instructions = method.Body.Instructions;
		for (int i = 0; i <= instructions.Count - 2; i++) {
			var ldsfld = instructions[i];
			if (ldsfld.OpCode.Code != Code.Ldsfld)
				continue;
			var field = ldsfld.Operand as IField;
			if (field == null || field.FieldSig.GetFieldType().GetElementType() != ElementType.String)
				continue;
			if (!new SigComparer().Equals(StringsEncodingClass, field.DeclaringType))
				continue;

			var call = instructions[i + 1];
			if (call.OpCode.Code != Code.Call)
				continue;
			var calledMethod = call.Operand as IMethod;
			if (!DotNetUtils.IsMethod(calledMethod, "System.Int32", "(System.String)"))
				continue;

			return field;
		}

		return null;
	}

	int? FindOffsetValue(MethodDef method, FieldDef offsetField, FieldDefAndDeclaringTypeDict<IField> fields) {
		var instructions = method.Body.Instructions;
		for (int i = 0; i <= instructions.Count - 2; i++) {
			var ldstr = instructions[i];
			if (ldstr.OpCode.Code != Code.Ldstr)
				continue;
			string stringVal = ldstr.Operand as string;
			if (stringVal == null)
				continue;

			var stsfld = instructions[i + 1];
			if (stsfld.OpCode.Code != Code.Stsfld)
				continue;
			var field = stsfld.Operand as IField;
			if (field == null || fields.Find(field) != offsetField)
				continue;

			if (!int.TryParse(stringVal, NumberStyles.Integer, null, out int value))
				continue;

			return value;
		}

		return null;
	}

	bool FindDecrypterMethod() {
		if (StringDecrypterMethod != null)
			return true;

		var methods = new List<MethodDef>(DotNetUtils.FindMethods(StringsEncodingClass.Methods, "System.String",
			new[] { "System.Int32" }));
		if (methods.Count == 0)
			return false;

		StringDecrypterMethod = methods[0];
		return true;
	}

	MethodDef FindSimpleZipTypeMethod(MethodDef method) {
		if (method == null || method.Body == null)
			return null;
		var instructions = method.Body.Instructions;
		for (int i = 0; i <= instructions.Count - 2; i++) {
			var call = instructions[i];
			if (call.OpCode.Code != Code.Call)
				continue;
			var calledMethod = call.Operand as MethodDef;
			if (calledMethod == null)
				continue;
			if (!DotNetUtils.IsMethod(calledMethod, "System.Byte[]", "(System.Byte[])"))
				continue;

			var stsfld = instructions[i + 1];
			if (stsfld.OpCode.Code != Code.Stsfld)
				continue;
			var field = stsfld.Operand as IField;
			if (field == null || field.FieldSig.GetFieldType().GetFullName() != "System.Byte[]")
				continue;
			if (!new SigComparer().Equals(StringsEncodingClass, field.DeclaringType))
				continue;

			return calledMethod;
		}

		return null;
	}

	public IEnumerable<FieldDef> GetAllStringDelegateFields() {
		if (GetStringDelegate == null)
			yield break;
		foreach (var type in module.GetTypes()) {
			foreach (var field in type.Fields) {
				if (field.FieldType.TryGetTypeDef() == GetStringDelegate)
					yield return field;
			}
		}
	}

	public void RemoveInitCode(Blocks blocks) {
		if (CreateStringDelegateMethod == null)
			return;

		if (CreateStringDelegateMethod.Parameters.Count != 0)
			RemoveInitCode_v2(blocks);
		else
			RemoveInitCode_v1(blocks);
	}

	void RemoveInitCode_v1(Blocks blocks) {
		foreach (var block in blocks.MethodBlocks.GetAllBlocks()) {
			var instructions = block.Instructions;
			for (int i = 0; i < instructions.Count; i++) {
				var call = instructions[i];
				if (call.OpCode != OpCodes.Call)
					continue;
				var method = call.Operand as IMethod;
				if (!MethodEqualityComparer.CompareDeclaringTypes.Equals(method, CreateStringDelegateMethod))
					continue;

				block.Remove(i, 1);
				break;
			}
		}
	}

	void RemoveInitCode_v2(Blocks blocks) {
		foreach (var block in blocks.MethodBlocks.GetAllBlocks()) {
			var instructions = block.Instructions;
			for (int i = 0; i <= instructions.Count - 3; i++) {
				var ldtoken = instructions[i];
				if (ldtoken.OpCode != OpCodes.Ldtoken)
					continue;
				if (!new SigComparer().Equals(blocks.Method.DeclaringType, ldtoken.Operand as ITypeDefOrRef))
					continue;

				var call1 = instructions[i + 1];
				if (call1.OpCode != OpCodes.Call)
					continue;
				var method1 = call1.Operand as IMethod;
				if (method1 == null || method1.ToString() !=
				    "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)")
					continue;

				var call2 = instructions[i + 2];
				if (call2.OpCode != OpCodes.Call)
					continue;
				var method2 = call2.Operand as IMethod;
				if (!MethodEqualityComparer.CompareDeclaringTypes.Equals(method2, CreateStringDelegateMethod))
					continue;

				block.Remove(i, 3);
				break;
			}
		}
	}
}
