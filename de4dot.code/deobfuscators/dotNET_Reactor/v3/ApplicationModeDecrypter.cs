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

using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v3;

class ApplicationModeDecrypter {
	readonly ModuleDefMD module;
	AssemblyResolver assemblyResolver;

	public ApplicationModeDecrypter(ModuleDefMD module) {
		this.module = module;
		Find();
	}

	public byte[] AssemblyKey => assemblyResolver.Key;
	public byte[] AssemblyIv => assemblyResolver.Iv;
	public MemoryPatcher MemoryPatcher { get; private set; }

	public bool Detected => assemblyResolver != null;

	void Find() {
		var cflowDeobfuscator = new CflowDeobfuscator(new MethodCallInliner(true));

		foreach (var type in module.Types) {
			if (DotNetUtils.GetPInvokeMethod(type, "kernel32", "CloseHandle") == null)
				continue;

			var resolver = new AssemblyResolver(type, cflowDeobfuscator);
			if (!resolver.Detected)
				continue;
			var patcher = new MemoryPatcher(type, cflowDeobfuscator);
			if (!patcher.Detected)
				continue;

			assemblyResolver = resolver;
			MemoryPatcher = patcher;
			return;
		}
	}
}
