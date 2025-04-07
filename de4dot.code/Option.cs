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
using System.Text.RegularExpressions;

namespace de4dot.code;

public abstract class Option {
	const string SHORTNAME_PREFIX = "-";
	const string LONGNAME_PREFIX = "--";

	public Option(string shortName, string longName, string description) {
		if (shortName != null)
			this.ShortName = SHORTNAME_PREFIX + shortName;
		if (longName != null)
			this.LongName = LONGNAME_PREFIX + longName;
		this.Description = description;
	}

	public string ShortName { get; }

	public string LongName { get; }

	public string Description { get; }

	public object Default { get; protected set; }

	public virtual bool NeedArgument => true;
	public virtual string ArgumentValueName => "value";

	// Returns true if the new value is set, or false on error. error string is also updated.
	public abstract bool Set(string val, out string error);
}

public class BoolOption : Option {
	bool val;

	public BoolOption(string shortName, string longName, string description, bool val)
		: base(shortName, longName, description) => Default = this.val = val;

	public override string ArgumentValueName => "bool";

	public override bool Set(string newVal, out string error) {
		if (string.Equals(newVal, "false", StringComparison.OrdinalIgnoreCase) ||
		    string.Equals(newVal, "off", StringComparison.OrdinalIgnoreCase) ||
		    string.Equals(newVal, "0", StringComparison.OrdinalIgnoreCase)) {
			val = false;
		}
		else
			val = true;

		error = "";
		return true;
	}

	public bool Get() => val;
}

public class IntOption : Option {
	int val;

	public IntOption(string shortName, string longName, string description, int val)
		: base(shortName, longName, description) => Default = this.val = val;

	public override string ArgumentValueName => "int";

	public override bool Set(string newVal, out string error) {
		if (!int.TryParse(newVal, out int newInt)) {
			error = $"Not an integer: '{newVal}'";
			return false;
		}

		val = newInt;
		error = "";
		return true;
	}

	public int Get() => val;
}

public class StringOption : Option {
	string val;

	public StringOption(string shortName, string longName, string description, string val)
		: base(shortName, longName, description) => Default = this.val = val;

	public override string ArgumentValueName => "string";

	public override bool Set(string newVal, out string error) {
		val = newVal;
		error = "";
		return true;
	}

	public string Get() => val;
}

public class NameRegexOption : Option {
	NameRegexes val;

	public NameRegexOption(string shortName, string longName, string description, string val)
		: base(shortName, longName, description) => Default = this.val = new NameRegexes(val);

	public override string ArgumentValueName => "regex";

	public override bool Set(string newVal, out string error) {
		try {
			var regexes = new NameRegexes();
			regexes.Set(newVal);
			val = regexes;
		}
		catch (ArgumentException) {
			error = $"Could not parse regex '{newVal}'";
			return false;
		}

		error = "";
		return true;
	}

	public NameRegexes Get() => val;
}

public class RegexOption : Option {
	Regex val;

	public RegexOption(string shortName, string longName, string description, string val)
		: base(shortName, longName, description) => Default = this.val = new Regex(val);

	public override string ArgumentValueName => "regex";

	public override bool Set(string newVal, out string error) {
		try {
			val = new Regex(newVal);
		}
		catch (ArgumentException) {
			error = $"Could not parse regex '{newVal}'";
			return false;
		}

		error = "";
		return true;
	}

	public Regex Get() => val;
}

public class NoArgOption : Option {
	readonly Action action;
	bool triggered;

	public NoArgOption(string shortName, string longName, string description)
		: this(shortName, longName, description, null) {
	}

	public NoArgOption(string shortName, string longName, string description, Action action)
		: base(shortName, longName, description) => this.action = action;

	public override bool NeedArgument => false;

	public override bool Set(string val, out string error) {
		triggered = true;
		action?.Invoke();
		error = "";
		return true;
	}

	public bool Get() => triggered;
}

public class OneArgOption : Option {
	readonly Action<string> action;
	readonly string typeName;

	public OneArgOption(string shortName, string longName, string description, string typeName, Action<string> action)
		: base(shortName, longName, description) {
		this.typeName = typeName ?? "value";
		this.action = action;
		Default = null;
	}

	public override string ArgumentValueName => typeName;

	public override bool Set(string val, out string error) {
		action(val);
		error = "";
		return true;
	}
}
