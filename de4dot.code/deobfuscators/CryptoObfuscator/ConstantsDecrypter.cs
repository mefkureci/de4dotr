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

namespace de4dot.code.deobfuscators.CryptoObfuscator;

class ConstantsDecrypter {
	static readonly string[] requiredTypes = new[] { "System.Byte[]", "System.Int32", "System.Int32" };

	readonly InitializedDataCreator initializedDataCreator;
	readonly ModuleDefMD module;
	byte[] constantsData;
	MethodDef methodArray;

	public ConstantsDecrypter(ModuleDefMD module, InitializedDataCreator initializedDataCreator) {
		this.module = module;
		this.initializedDataCreator = initializedDataCreator;
	}

	public TypeDef Type { get; private set; }

	public EmbeddedResource Resource { get; private set; }

	public MethodDef Int32Decrypter { get; private set; }

	public MethodDef Int64Decrypter { get; private set; }

	public MethodDef SingleDecrypter { get; private set; }

	public MethodDef DoubleDecrypter { get; private set; }

	public bool Detected => Type != null;

	public void Find() {
		foreach (var type in module.Types) {
			if (!CheckType(type))
				continue;

			Type = type;
			return;
		}
	}

	bool CheckType(TypeDef type) {
		if (type.Methods.Count != 7)
			return false;
		if (type.Fields.Count < 1 || type.Fields.Count > 3)
			return false;
		if (!new FieldTypes(type).All(requiredTypes))
			return false;
		if (!CheckMethods(type))
			return false;

		return true;
	}

	bool CheckMethods(TypeDef type) {
		Int32Decrypter = DotNetUtils.GetMethod(type, "System.Int32", "(System.Int32)");
		Int64Decrypter = DotNetUtils.GetMethod(type, "System.Int64", "(System.Int32)");
		SingleDecrypter = DotNetUtils.GetMethod(type, "System.Single", "(System.Int32)");
		DoubleDecrypter = DotNetUtils.GetMethod(type, "System.Double", "(System.Int32)");
		methodArray = DotNetUtils.GetMethod(type, "System.Void", "(System.Array,System.Int32)");

		return Int32Decrypter != null && Int64Decrypter != null &&
		       SingleDecrypter != null && DoubleDecrypter != null &&
		       methodArray != null;
	}

	public void Initialize(ResourceDecrypter resourceDecrypter) {
		if (Type == null)
			return;

		var cctor = Type.FindStaticConstructor();
		Resource = CoUtils.GetResource(module, DotNetUtils.GetCodeStrings(cctor));

		//if the return value is null, it is possible that resource name is encrypted
		if (Resource == null) {
			string[] Resources = new[] { CoUtils.DecryptResourceName(module, cctor) };
			Resource = CoUtils.GetResource(module, Resources);
		}

		constantsData = resourceDecrypter.Decrypt(Resource.CreateReader().AsStream());
	}

	public int DecryptInt32(int index) => BitConverter.ToInt32(constantsData, index);
	public long DecryptInt64(int index) => BitConverter.ToInt64(constantsData, index);
	public float DecryptSingle(int index) => BitConverter.ToSingle(constantsData, index);
	public double DecryptDouble(int index) => BitConverter.ToDouble(constantsData, index);

	public void Deobfuscate(Blocks blocks) {
		var infos = new List<ArrayInfo>();
		foreach (var block in blocks.MethodBlocks.GetAllBlocks()) {
			var instrs = block.Instructions;
			infos.Clear();

			for (int i = 0; i < instrs.Count - 5; i++) {
				int index = i;

				var ldci4_arySize = instrs[index++];
				if (!ldci4_arySize.IsLdcI4())
					continue;

				var newarr = instrs[index++];
				if (newarr.OpCode.Code != Code.Newarr)
					continue;
				var arrayType = module.CorLibTypes.GetCorLibTypeSig(newarr.Operand as ITypeDefOrRef);
				if (arrayType == null)
					continue;

				if (instrs[index++].OpCode.Code != Code.Dup)
					continue;

				var ldci4_index = instrs[index++];
				if (!ldci4_index.IsLdcI4())
					continue;

				var call = instrs[index++];
				if (call.OpCode.Code != Code.Call && call.OpCode.Code != Code.Callvirt)
					continue;
				if (!MethodEqualityComparer.CompareDeclaringTypes.Equals(call.Operand as IMethod, methodArray))
					continue;

				if (arrayType.ElementType.GetPrimitiveSize() == -1) {
					Logger.w("Can't decrypt non-primitive type array in method {0:X8}",
						blocks.Method.MDToken.ToInt32());
					continue;
				}

				infos.Add(new ArrayInfo(i, index - i, arrayType, ldci4_arySize.GetLdcI4Value(),
					ldci4_index.GetLdcI4Value()));
			}

			infos.Reverse();
			foreach (var info in infos) {
				int elemSize = info.arrayType.ElementType.GetPrimitiveSize();
				byte[] decrypted = DecryptArray(info);
				initializedDataCreator.AddInitializeArrayCode(block, info.start, info.len,
					info.arrayType.ToTypeDefOrRef(), decrypted);
				Logger.v("Decrypted {0} array: {1} elements", info.arrayType.ToString(), decrypted.Length / elemSize);
			}
		}
	}

	byte[] DecryptArray(ArrayInfo aryInfo) {
		byte[] ary = new byte[aryInfo.arySize * aryInfo.arrayType.ElementType.GetPrimitiveSize()];
		int dataIndex = aryInfo.index;
		int len = DeobUtils.ReadVariableLengthInt32(constantsData, ref dataIndex);
		Buffer.BlockCopy(constantsData, dataIndex, ary, 0, len);
		return ary;
	}

	struct ArrayInfo {
		public readonly CorLibTypeSig arrayType;
		public readonly int start;
		public readonly int len;
		public readonly int arySize;
		public readonly int index;

		public ArrayInfo(int start, int len, CorLibTypeSig arrayType, int arySize, int index) {
			this.start = start;
			this.len = len;
			this.arrayType = arrayType;
			this.arySize = arySize;
			this.index = index;
		}
	}
}
