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
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.dotNET_Reactor.v3;

class DecryptMethod {
	MethodDef decryptionMethod;

	public byte[] Key { get; private set; }

	public byte[] Iv { get; private set; }

	public bool Detected => decryptionMethod != null;

	public static bool CouldBeDecryptMethod(MethodDef method, IEnumerable<string> additionalTypes) {
		if (method.Body == null)
			return false;

		var localTypes = new LocalTypes(method);
		var requiredTypes = new List<string> {
			"System.Byte[]",
			"System.IO.MemoryStream",
			"System.Security.Cryptography.CryptoStream",
			"System.Security.Cryptography.ICryptoTransform"
		};
		requiredTypes.AddRange(additionalTypes);
		if (!localTypes.All(requiredTypes))
			return false;
		if (!localTypes.Exists("System.Security.Cryptography.RijndaelManaged") &&
		    !localTypes.Exists("System.Security.Cryptography.AesManaged"))
			return false;

		return true;
	}

	public bool GetKey(MethodDef method) {
		byte[] tmpKey = ArrayFinder.GetInitializedByteArray(method, 32);
		if (tmpKey == null)
			return false;
		byte[] tmpIv = ArrayFinder.GetInitializedByteArray(method, 16);
		if (tmpIv == null)
			return false;

		decryptionMethod = method;
		Key = tmpKey;
		Iv = tmpIv;
		return true;
	}
}
