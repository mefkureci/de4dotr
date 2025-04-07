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

namespace de4dot.code.deobfuscators.Agile_NET;

class CliSecureRtType {
	static readonly string[] requiredFields1 = new[] { "System.Boolean" };

	static readonly string[] requiredFields6 = new[] { "System.Byte[]" };

	static readonly string[] requiredFields7 = new[] { "System.Byte[]", "System.Collections.Hashtable" };

	readonly ModuleDefMD module;
	readonly Dictionary<StringDecrypterInfo, bool> stringDecrypterInfos = new();
	bool foundSig;
	public CliSecureRtType(ModuleDefMD module) => this.module = module;

	public CliSecureRtType(ModuleDefMD module, CliSecureRtType oldOne) {
		this.module = module;
		Type = Lookup(oldOne.Type, "Could not find CliSecureRt type");
		PostInitializeMethod = Lookup(oldOne.PostInitializeMethod, "Could not find postInitializeMethod method");
		InitializeMethod = Lookup(oldOne.InitializeMethod, "Could not find initializeMethod method");
		foreach (var info in oldOne.stringDecrypterInfos.Keys) {
			var m = Lookup(info.Method, "Could not find string decrypter method");
			var f = Lookup(info.Field, "Could not find string decrypter field");
			stringDecrypterInfos[new StringDecrypterInfo(m, f)] = true;
		}

		LoadMethod = Lookup(oldOne.LoadMethod, "Could not find loadMethod method");
		foundSig = oldOne.foundSig;
	}

	public bool Detected => foundSig || Type != null;
	public TypeDef Type { get; private set; }

	public IEnumerable<StringDecrypterInfo> StringDecrypterInfos => stringDecrypterInfos.Keys;
	public MethodDef PostInitializeMethod { get; private set; }

	public MethodDef InitializeMethod { get; private set; }

	public MethodDef LoadMethod { get; private set; }

	T Lookup<T>(T def, string errorMessage) where T : class, ICodedToken => DeobUtils.Lookup(module, def, errorMessage);

	public void Find(byte[] moduleBytes) {
		if (Type != null)
			return;
		if (Find2())
			return;
		if (Find3())
			return;
		FindNativeCode(moduleBytes);
	}

	bool Find2() {
		foreach (var cctor in DeobUtils.GetInitCctors(module, 3)) {
			foreach (var calledMethod in DotNetUtils.GetCalledMethods(module, cctor)) {
				var type = calledMethod.DeclaringType;
				if (type.IsPublic)
					continue;
				var fieldTypes = new FieldTypes(type);
				if (!fieldTypes.All(requiredFields1))
					continue;
				if (!HasInitializeMethod(type, "_Initialize") && !HasInitializeMethod(type, "_Initialize64"))
					continue;

				InitializeMethod = calledMethod;
				PostInitializeMethod = FindMethod(type, "System.Void", "PostInitialize", "()");
				LoadMethod = FindMethod(type, "System.IntPtr", "Load", "()");
				Type = type;
				FindStringDecrypters();
				return true;
			}
		}

		return false;
	}

	void FindStringDecrypters() => AddStringDecrypterMethod(FindStringDecrypterMethod(Type));

	void AddStringDecrypterMethod(MethodDef method) {
		if (method != null)
			stringDecrypterInfos[new StringDecrypterInfo(method)] = true;
	}

	bool Find3() {
		foreach (var type in module.Types) {
			if (type.Fields.Count < 1 || type.Fields.Count > 2)
				continue;
			var fieldTypes = new FieldTypes(type);
			if (!fieldTypes.Exactly(requiredFields6) && !fieldTypes.Exactly(requiredFields7))
				continue;
			if (type.Methods.Count != 2)
				continue;
			if (type.FindStaticConstructor() == null)
				continue;
			var cs = type.FindMethod("cs");
			if (cs == null)
				continue;

			AddStringDecrypterMethod(cs);
			Type = type;
			return true;
		}

		return false;
	}

	static MethodDef FindStringDecrypterMethod(TypeDef type) {
		foreach (var method in type.Methods) {
			if (method.Body == null || !method.IsStatic)
				continue;
			if (!DotNetUtils.IsMethod(method, "System.String", "(System.String)"))
				continue;

			return method;
		}

		return null;
	}

	static MethodDef FindMethod(TypeDef type, string returnType, string name, string parameters) {
		string methodName = returnType + " " + type.FullName + "::" + name + parameters;
		foreach (var method in type.Methods) {
			if (method.Body == null || !method.IsStatic)
				continue;
			if (method.FullName != methodName)
				continue;

			return method;
		}

		return null;
	}

	static bool HasInitializeMethod(TypeDef type, string name) {
		var method = DotNetUtils.GetPInvokeMethod(type, name);
		if (method == null)
			return false;
		var sig = method.MethodSig;
		if (sig.Params.Count != 1)
			return false;
		if (sig.Params[0].GetElementType() != ElementType.I)
			return false;
		var retType = sig.RetType.GetElementType();
		if (retType != ElementType.Void && retType != ElementType.I4)
			return false;
		return true;
	}

	bool FindNativeCode(byte[] moduleBytes) {
		byte[] bytes = moduleBytes ?? DeobUtils.ReadModule(module);
		using (var peImage = new MyPEImage(bytes))
			return foundSig = MethodsDecrypter.Detect(peImage);
	}

	public bool IsAtLeastVersion50() => DotNetUtils.HasPinvokeMethod(Type, "LoadLibraryA");

	public void FindStringDecrypterMethod() {
		if (Type != null)
			return;

		foreach (var type in module.Types) {
			if (type.Fields.Count != 0)
				continue;
			if (type.Methods.Count != 1)
				continue;
			var cs = type.Methods[0];
			if (!IsOldStringDecrypterMethod(cs))
				continue;

			Type = type;
			AddStringDecrypterMethod(cs);
			return;
		}
	}

	static bool IsOldStringDecrypterMethod(MethodDef method) {
		if (method == null || method.Body == null || !method.IsStatic)
			return false;
		if (!DotNetUtils.IsMethod(method, "System.String", "(System.String)"))
			return false;
		if (!DeobUtils.HasInteger(method, 0xFF))
			return false;

		return true;
	}
}
