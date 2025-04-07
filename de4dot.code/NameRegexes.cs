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
using System.Text.RegularExpressions;

namespace de4dot.code;

public class NameRegex {
	public const char invertChar = '!';
	readonly Regex regex;

	public NameRegex(string regex) {
		if (regex.Length > 0 && regex[0] == invertChar) {
			regex = regex.Substring(1);
			MatchValue = false;
		}
		else
			MatchValue = true;

		this.regex = new Regex(regex);
	}

	public bool MatchValue { get; }

	// Returns true if the regex matches. Use MatchValue to get result.
	public bool IsMatch(string s) => regex.IsMatch(s);

	public override string ToString() {
		if (!MatchValue)
			return invertChar + regex.ToString();
		return regex.ToString();
	}
}

public class NameRegexes {
	public const char regexSeparatorChar = '&';

	public NameRegexes() : this("") { }
	public NameRegexes(string regex) => Set(regex);
	public bool DefaultValue { get; set; }
	public IList<NameRegex> Regexes { get; private set; }

	public void Set(string regexesString) {
		Regexes = new List<NameRegex>();
		if (regexesString != "") {
			foreach (string regex in regexesString.Split(regexSeparatorChar))
				Regexes.Add(new NameRegex(regex));
		}
	}

	public bool IsMatch(string s) {
		foreach (var regex in Regexes) {
			if (regex.IsMatch(s))
				return regex.MatchValue;
		}

		return DefaultValue;
	}

	public override string ToString() {
		string s = "";
		for (int i = 0; i < Regexes.Count; i++) {
			if (i > 0)
				s += regexSeparatorChar;
			s += Regexes[i].ToString();
		}

		return s;
	}
}
