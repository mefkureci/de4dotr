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
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.Skater_NET;

class StringDecrypter {
	static readonly string[] callsMethodsV2 = new[] {
		"System.String[] System.String::Split(System.Char[])", "System.Int32 System.Array::GetUpperBound(System.Int32)",
		"System.String Microsoft.VisualBasic.CompilerServices.Conversions::ToString(System.Char)",
		"System.Int32 Microsoft.VisualBasic.CompilerServices.Conversions::ToInteger(System.String)",
		"System.String System.String::Concat(System.String,System.String)",
		"System.Char Microsoft.VisualBasic.Strings::Chr(System.Int32)"
	};

	readonly FieldDefAndDeclaringTypeDict<string> fieldToDecryptedString = new();
	readonly ModuleDefMD module;
	IDecrypter decrypter;
	MethodDef decrypterCctor;
	public StringDecrypter(ModuleDefMD module) => this.module = module;

	public bool Detected => Type != null;
	public bool CanRemoveType { get; private set; }

	public TypeDef Type { get; private set; }

	public void Find() {
		foreach (var type in module.Types) {
			if (type.HasProperties || type.HasEvents)
				continue;

			var cctor = type.FindStaticConstructor();
			if (cctor == null)
				continue;

			if (CheckType(type)) {
				CanRemoveType = true;
				Type = type;
				decrypterCctor = cctor;
				return;
			}
		}
	}

	public void Initialize(ISimpleDeobfuscator deobfuscator) {
		if (decrypterCctor == null)
			return;

		deobfuscator.Deobfuscate(decrypterCctor);
		var instrs = decrypterCctor.Body.Instructions;
		for (int i = 0; i < instrs.Count - 4; i++) {
			var ldstr = instrs[i];
			if (ldstr.OpCode.Code != Code.Ldstr)
				continue;
			string encryptedString = ldstr.Operand as string;
			if (encryptedString == null)
				continue;
			if (instrs[i + 1].OpCode.Code != Code.Stsfld)
				continue;
			if (instrs[i + 2].OpCode.Code != Code.Ldsfld)
				continue;
			if (instrs[i + 3].OpCode.Code != Code.Call)
				continue;
			if (instrs[i + 4].OpCode.Code != Code.Stsfld)
				continue;
			var field = instrs[i + 4].Operand as FieldDef;
			if (field == null)
				continue;
			if (!new SigComparer().Equals(field.DeclaringType, Type))
				continue;

			fieldToDecryptedString.Add(field, decrypter.Decrypt(encryptedString));
		}
	}

	bool CheckType(TypeDef type) {
		foreach (var method in type.Methods) {
			if (!method.IsStatic || method.Body == null)
				continue;
			if (!DotNetUtils.IsMethod(method, "System.String", "(System.String)"))
				continue;

			if (CheckMethodV1(method))
				return true;
			if (CheckMethodV2(method))
				return true;
		}

		return false;
	}

	bool CheckMethodV1(MethodDef method) {
		byte[] salt = GetSalt(method);
		if (salt == null)
			return false;

		string password = GetPassword(method);
		if (string.IsNullOrEmpty(password))
			return false;

		var passwordBytes = new PasswordDeriveBytes(password, salt);
		byte[] key = passwordBytes.GetBytes(16);
		byte[] iv = passwordBytes.GetBytes(8);
		decrypter = new DecrypterV1(key, iv);
		return true;
	}

	bool CheckMethodV2(MethodDef method) {
		if (!DeobUtils.HasInteger(method, ' '))
			return false;
		foreach (string calledMethodName in callsMethodsV2) {
			if (!DotNetUtils.CallsMethod(method, calledMethodName))
				return false;
		}

		decrypter = new DecrypterV2();
		return true;
	}

	static byte[] GetSalt(MethodDef method) {
		foreach (string s in DotNetUtils.GetCodeStrings(method)) {
			byte[] saltAry = FixSalt(s);
			if (saltAry != null)
				return saltAry;
		}

		return null;
	}

	static byte[] FixSalt(string s) {
		if (s.Length < 10 || s.Length > 30 || s.Length / 2 * 2 != s.Length)
			return null;

		char[] ary = s.ToCharArray();
		Array.Reverse(ary);
		for (int i = 0; i < ary.Length; i++)
			ary[i]--;
		string s2 = new(ary);

		byte[] saltAry = new byte[(int)Math.Round((double)s2.Length / 2 - 1) + 1];
		for (int i = 0; i < saltAry.Length; i++) {
			if (!int.TryParse(s2.Substring(i * 2, 2), NumberStyles.AllowHexSpecifier, null, out int result))
				return null;
			saltAry[i] = (byte)result;
		}

		return saltAry;
	}

	string GetPassword(MethodDef decryptMethod) {
		foreach (var method in DotNetUtils.GetCalledMethods(module, decryptMethod)) {
			if (!method.IsStatic || method.Body == null)
				continue;
			if (!new SigComparer().Equals(method.DeclaringType, decryptMethod.DeclaringType))
				continue;
			if (!DotNetUtils.IsMethod(method, "System.String", "()"))
				continue;

			string hexChars = GetPassword2(method);
			if (string.IsNullOrEmpty(hexChars))
				continue;

			string password = FixPassword(hexChars);
			if (string.IsNullOrEmpty(password))
				continue;

			return password;
		}

		return null;
	}

	string FixPassword(string hexChars) {
		string[] ary = hexChars.Trim().Split(' ');
		string password = "";
		for (int i = 0; i < ary.Length; i++) {
			if (!int.TryParse(ary[i], NumberStyles.AllowHexSpecifier, null, out int result))
				return null;
			password += (char)result;
		}

		return password;
	}

	string GetPassword2(MethodDef method) {
		string password = "";
		foreach (var calledMethod in DotNetUtils.GetCalledMethods(module, method)) {
			string s = GetPassword3(calledMethod);
			if (string.IsNullOrEmpty(s))
				return null;

			password += s;
		}

		return password;
	}

	string GetPassword3(MethodDef method) {
		var strings = new List<string>(DotNetUtils.GetCodeStrings(method));
		if (strings.Count != 1)
			return null;

		string s = strings[0];
		if (!Regex.IsMatch(s, @"^[a-fA-F0-9]{2} $"))
			return null;

		return s;
	}

	public void Deobfuscate(Blocks blocks) {
		foreach (var block in blocks.MethodBlocks.GetAllBlocks()) {
			var instrs = block.Instructions;
			for (int i = 0; i < instrs.Count; i++) {
				var instr = instrs[i];

				if (instr.OpCode.Code == Code.Call || instr.OpCode.Code == Code.Callvirt) {
					if (blocks.Method.DeclaringType == Type)
						continue;
					if (instr.Operand is IMethod calledMethod && calledMethod.DeclaringType == Type)
						CanRemoveType = false;
				}
				else if (instr.OpCode.Code == Code.Ldsfld) {
					if (instr.OpCode.Code != Code.Ldsfld)
						continue;
					var field = instr.Operand as IField;
					if (field == null)
						continue;
					string decrypted = fieldToDecryptedString.Find(field);
					if (decrypted == null)
						continue;

					instrs[i] = new Instr(OpCodes.Ldstr.ToInstruction(decrypted));
					Logger.v("Decrypted string: {0}", Utils.ToCsharpString(decrypted));
				}
			}
		}
	}

	interface IDecrypter {
		string Decrypt(string encrypted);
	}

	class DecrypterV1 : IDecrypter {
		readonly byte[] iv;
		readonly byte[] key;

		public DecrypterV1(byte[] key, byte[] iv) {
			this.key = key;
			this.iv = iv;
		}

		public string Decrypt(string encrypted) {
			try {
				return Encoding.Unicode.GetString(DeobUtils.Des3Decrypt(Convert.FromBase64String(encrypted), key, iv));
			}
			catch (FormatException) {
				return "";
			}
		}
	}

	class DecrypterV2 : IDecrypter {
		public string Decrypt(string encrypted) {
			string[] ints = encrypted.Split(' ');
			if (ints.Length % 3 != 0)
				throw new ApplicationException("Invalid encrypted string");
			var sb = new StringBuilder(ints.Length / 3);
			for (int i = 0; i < ints.Length; i += 3) {
				int val1 = int.Parse(ints[i]);
				int val2 = int.Parse(ints[i + 1]);
				if (val2 / 2.0 == Math.Round(val2 / 2.0))
					val1 += val1;
				sb.Append((char)val1);
			}

			return sb.ToString();
		}
	}
}
