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

using System.Collections.Generic;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.CodeVeil;

// Detects the type CV adds to the assembly that gets called from <Module>::.cctor.
class MainType {
	static readonly string[] fieldTypesV5 = new[] {
		"System.Byte[]", "System.Collections.Generic.List`1<System.Delegate>", "System.Runtime.InteropServices.GCHandle"
	};

	readonly ModuleDefMD module;

	public MainType(ModuleDefMD module) => this.module = module;

	public MainType(ModuleDefMD module, MainType oldOne) {
		this.module = module;
		Type = Lookup(oldOne.Type, "Could not find main type");
		InitMethod = Lookup(oldOne.InitMethod, "Could not find main type init method");
		TamperCheckMethod = Lookup(oldOne.TamperCheckMethod, "Could not find tamper detection method");
		Version = oldOne.Version;
		Rvas = oldOne.Rvas;
		foreach (var otherInitMethod in OtherInitMethods)
			OtherInitMethods.Add(Lookup(otherInitMethod, "Could not find otherInitMethod"));
	}

	public bool Detected => Type != null;
	public ObfuscatorVersion Version { get; private set; } = ObfuscatorVersion.Unknown;

	public TypeDef Type { get; private set; }

	public MethodDef InitMethod { get; private set; }

	public List<MethodDef> OtherInitMethods { get; private set; } = new();

	public MethodDef TamperCheckMethod { get; private set; }

	public List<uint> Rvas { get; private set; } = new();

	T Lookup<T>(T def, string errorMessage) where T : class, ICodedToken =>
		DeobUtils.Lookup(module, def, errorMessage);

	public void Find() {
		var cctor = DotNetUtils.GetModuleTypeCctor(module);
		if (cctor == null)
			return;

		var instrs = cctor.Body.Instructions;
		for (int i = 0; i < instrs.Count - 2; i++) {
			var ldci4_1 = instrs[i];
			if (!ldci4_1.IsLdcI4())
				continue;

			var ldci4_2 = instrs[i + 1];
			if (!ldci4_2.IsLdcI4())
				continue;

			var call = instrs[i + 2];
			if (call.OpCode.Code != Code.Call)
				continue;
			var initMethodTmp = call.Operand as MethodDef;
			if (!CheckInitMethod(initMethodTmp, out var obfuscatorVersionTmp))
				continue;
			if (!CheckMethodsType(initMethodTmp.DeclaringType))
				continue;

			Version = obfuscatorVersionTmp;
			Type = initMethodTmp.DeclaringType;
			InitMethod = initMethodTmp;
			break;
		}
	}

	bool CheckInitMethod(MethodDef initMethod, out ObfuscatorVersion obfuscatorVersionTmp) {
		obfuscatorVersionTmp = ObfuscatorVersion.Unknown;

		if (initMethod == null)
			return false;
		if (initMethod.Body == null)
			return false;
		if (!initMethod.IsStatic)
			return false;
		if (!DotNetUtils.IsMethod(initMethod, "System.Void", "(System.Boolean,System.Boolean)"))
			return false;

		if (HasCodeString(initMethod, "E_FullTrust")) {
			if (DotNetUtils.GetPInvokeMethod(initMethod.DeclaringType, "user32", "CallWindowProcW") != null)
				obfuscatorVersionTmp = ObfuscatorVersion.V4_1;
			else
				obfuscatorVersionTmp = ObfuscatorVersion.V4_0;
		}
		else if (HasCodeString(initMethod, "Full Trust Required"))
			obfuscatorVersionTmp = ObfuscatorVersion.V3;
		else if (initMethod.DeclaringType.HasNestedTypes && new FieldTypes(initMethod.DeclaringType).All(fieldTypesV5))
			obfuscatorVersionTmp = ObfuscatorVersion.V5_0;
		else
			return false;

		return true;
	}

	static bool HasCodeString(MethodDef method, string str) {
		foreach (string s in DotNetUtils.GetCodeStrings(method)) {
			if (s == str)
				return true;
		}

		return false;
	}

	bool CheckMethodsType(TypeDef type) {
		Rvas = new List<uint>();

		var fields = GetRvaFields(type);
		if (fields.Count < 2) // RVAs for executive and stub are always present if encrypted methods
			return true;

		foreach (var field in fields)
			Rvas.Add((uint)field.RVA);
		return true;
	}

	static List<FieldDef> GetRvaFields(TypeDef type) {
		var fields = new List<FieldDef>();
		foreach (var field in type.Fields) {
			var etype = field.FieldSig.GetFieldType().GetElementType();
			if (etype != ElementType.U1 && etype != ElementType.U4)
				continue;
			if (field.RVA == 0)
				continue;

			fields.Add(field);
		}

		return fields;
	}

	public void Initialize() {
		if (Type == null)
			return;

		TamperCheckMethod = FindTamperCheckMethod();
		OtherInitMethods = FindOtherInitMethods();
	}

	MethodDef FindTamperCheckMethod() {
		foreach (var method in Type.Methods) {
			if (!method.IsStatic || method.Body == null)
				continue;
			if (!DotNetUtils.IsMethod(method, "System.Void", "(System.Reflection.Assembly,System.UInt64)"))
				continue;

			return method;
		}

		return null;
	}

	List<MethodDef> FindOtherInitMethods() {
		var list = new List<MethodDef>();
		foreach (var method in Type.Methods) {
			if (!method.IsStatic)
				continue;
			if (method.Name == ".cctor")
				continue;
			if (!DotNetUtils.IsMethod(method, "System.Void", "()"))
				continue;

			list.Add(method);
		}

		return list;
	}

	public MethodDef GetInitStringDecrypterMethod(MethodDef stringDecrypterInitMethod) {
		if (stringDecrypterInitMethod == null)
			return null;
		if (Type == null)
			return null;

		foreach (var method in Type.Methods) {
			if (!method.IsStatic || method.Body == null)
				continue;
			if (CallsMethod(method, stringDecrypterInitMethod))
				return method;
		}

		return null;
	}

	bool CallsMethod(MethodDef methodToCheck, MethodDef calledMethod) {
		foreach (var method in DotNetUtils.GetCalledMethods(module, methodToCheck)) {
			if (method == calledMethod)
				return true;
		}

		return false;
	}

	public void RemoveInitCall(Blocks blocks) {
		if (InitMethod == null || Type == null)
			return;
		if (blocks.Method.Name != ".cctor")
			return;
		if (blocks.Method.DeclaringType != DotNetUtils.GetModuleType(module))
			return;

		foreach (var block in blocks.MethodBlocks.GetAllBlocks()) {
			var instrs = block.Instructions;
			for (int i = 0; i < instrs.Count - 2; i++) {
				if (!instrs[i].IsLdcI4())
					continue;
				if (!instrs[i + 1].IsLdcI4())
					continue;
				var call = instrs[i + 2];
				if (call.OpCode.Code != Code.Call)
					continue;
				if (call.Operand != InitMethod)
					continue;

				block.Remove(i, 3);
				return;
			}
		}
	}
}
