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

namespace de4dot.code.deobfuscators.Agile_NET.vm.v1;

class UnknownHandlerInfo {
	readonly CsvmInfo csvmInfo;
	readonly FieldsInfo fieldsInfo;
	readonly TypeDef type;

	public UnknownHandlerInfo(TypeDef type, CsvmInfo csvmInfo) {
		this.type = type;
		this.csvmInfo = csvmInfo;
		fieldsInfo = new FieldsInfo(GetFields(type));
		CountMethods();
		FindOverrideMethods();
		ExecuteMethodThrows = CountThrows(ExecuteMethod);
		ExecuteMethodPops = CountPops(ExecuteMethod);
	}

	public MethodDef ReadMethod { get; private set; }

	public MethodDef ExecuteMethod { get; private set; }

	public int NumStaticMethods { get; private set; }

	public int NumInstanceMethods { get; private set; }

	public int NumVirtualMethods { get; private set; }

	public int ExecuteMethodThrows { get; }

	public int ExecuteMethodPops { get; }

	public int NumCtors { get; private set; }

	internal static IEnumerable<FieldDef> GetFields(TypeDef type) {
		var typeFields = new FieldDefAndDeclaringTypeDict<FieldDef>();
		foreach (var field in type.Fields)
			typeFields.Add(field, field);
		var realFields = new Dictionary<FieldDef, bool>();
		foreach (var method in type.Methods) {
			if (method.Body == null)
				continue;
			foreach (var instr in method.Body.Instructions) {
				var fieldRef = instr.Operand as IField;
				if (fieldRef == null)
					continue;
				var field = typeFields.Find(fieldRef);
				if (field == null)
					continue;
				realFields[field] = true;
			}
		}

		return realFields.Keys;
	}

	void CountMethods() {
		foreach (var method in type.Methods) {
			if (method.Name == ".cctor") {
			}
			else if (method.Name == ".ctor")
				NumCtors++;
			else if (method.IsStatic)
				NumStaticMethods++;
			else if (method.IsVirtual)
				NumVirtualMethods++;
			else
				NumInstanceMethods++;
		}
	}

	void FindOverrideMethods() {
		foreach (var method in type.Methods) {
			if (!method.IsVirtual)
				continue;
			if (DotNetUtils.IsMethod(method, "System.Void", "(System.IO.BinaryReader)")) {
				if (ReadMethod != null)
					throw new ApplicationException("Found another read method");
				ReadMethod = method;
			}
			else if (!DotNetUtils.HasReturnValue(method) && method.MethodSig.GetParamCount() == 1) {
				if (ExecuteMethod != null)
					throw new ApplicationException("Found another execute method");
				ExecuteMethod = method;
			}
		}

		if (ReadMethod == null)
			throw new ApplicationException("Could not find read method");
		if (ExecuteMethod == null)
			throw new ApplicationException("Could not find execute method");
	}

	static int CountThrows(MethodDef method) {
		int count = 0;
		foreach (var instr in method.Body.Instructions) {
			if (instr.OpCode.Code == Code.Throw)
				count++;
		}

		return count;
	}

	int CountPops(MethodDef method) {
		int count = 0;
		foreach (var instr in method.Body.Instructions) {
			if (instr.OpCode.Code != Code.Call && instr.OpCode.Code != Code.Callvirt)
				continue;
			var calledMethod = instr.Operand as IMethod;
			if (!MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod, csvmInfo.PopMethod))
				continue;

			count++;
		}

		return count;
	}

	public bool HasSameFieldTypes(object[] fieldTypes) => new FieldsInfo(fieldTypes).IsSame(fieldsInfo);
}
