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
using de4dot.blocks;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v3;

// Finds the type that saves the native lib (if in resources) to disk
class NativeLibSaver {
	readonly ModuleDefMD module;
	public NativeLibSaver(ModuleDefMD module) => this.module = module;

	public NativeLibSaver(ModuleDefMD module, NativeLibSaver oldOne) {
		this.module = module;
		Type = Lookup(oldOne.Type, "Could not find nativeLibCallerType");
		InitMethod = Lookup(oldOne.InitMethod, "Could not find initMethod");
		if (oldOne.Resource != null) {
			Resource = DotNetUtils.GetResource(module, oldOne.Resource.Name.String);
			if (Resource == null)
				throw new ApplicationException("Could not find nativeFileResource");
		}
	}

	public TypeDef Type { get; private set; }

	public MethodDef InitMethod { get; private set; }

	public Resource Resource { get; private set; }

	public bool Detected => Type != null;

	T Lookup<T>(T def, string errorMessage) where T : class, ICodedToken =>
		DeobUtils.Lookup(module, def, errorMessage);

	public void Find() {
		foreach (var calledMethod in DotNetUtils.GetCalledMethods(module, DotNetUtils.GetModuleTypeCctor(module))) {
			if (!DotNetUtils.IsMethod(calledMethod, "System.Void", "()"))
				continue;
			if (calledMethod.DeclaringType.FullName !=
			    "<PrivateImplementationDetails>{F1C5056B-0AFC-4423-9B83-D13A26B48869}")
				continue;

			Type = calledMethod.DeclaringType;
			InitMethod = calledMethod;
			foreach (string s in DotNetUtils.GetCodeStrings(InitMethod)) {
				Resource = DotNetUtils.GetResource(module, s);
				if (Resource != null)
					break;
			}

			return;
		}
	}
}
