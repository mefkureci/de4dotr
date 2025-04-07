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
using dnlib.DotNet;

namespace de4dot.code;

public class Logger : ILogger {
	public static readonly Logger Instance = new();
	readonly Dictionary<string, bool> ignoredMessages = new(StringComparer.Ordinal);
	readonly int indentSize;

	int indentLevel;
	string indentString = "";

	public Logger() : this(2, true) { }

	public Logger(int indentSize, bool canIgnoreMessages) {
		this.indentSize = indentSize;
		this.CanIgnoreMessages = canIgnoreMessages;
	}

	public int IndentLevel {
		get => indentLevel;
		set {
			if (indentLevel == value)
				return;
			indentLevel = value;
			InitIndentString();
		}
	}

	public LoggerEvent MaxLoggerEvent { get; set; } = LoggerEvent.Info;

	public bool CanIgnoreMessages { get; set; }

	public int NumIgnoredMessages { get; private set; }

	public void Log(object sender, LoggerEvent loggerEvent, string format, params object[] args) =>
		Log(true, sender, loggerEvent, format, args);

	public bool IgnoresEvent(LoggerEvent loggerEvent) => loggerEvent > MaxLoggerEvent;

	void InitIndentString() {
		if (indentLevel < 0)
			indentLevel = 0;
		indentString = new string(' ', indentLevel * indentSize);
	}

	public void Indent() {
		indentLevel++;
		InitIndentString();
	}

	public void DeIndent() {
		indentLevel--;
		InitIndentString();
	}

	public void LogErrorDontIgnore(string format, params object[] args) =>
		Log(false, null, LoggerEvent.Error, format, args);

	public void Log(bool canIgnore, object sender, LoggerEvent loggerEvent, string format, params object[] args) {
		if (IgnoresEvent(loggerEvent))
			return;
		if (canIgnore && IgnoreMessage(loggerEvent, format, args))
			return;

		switch (loggerEvent) {
		case LoggerEvent.Error:
			foreach (string l in string.Format(format, args).Split('\n'))
				LogMessage(string.Empty, $"ERROR: {l}");
			break;

		case LoggerEvent.Warning:
			foreach (string l in string.Format(format, args).Split('\n'))
				LogMessage(string.Empty, $"WARNING: {l}");
			break;

		default:
			string indent = loggerEvent <= LoggerEvent.Warning ? "" : indentString;
			LogMessage(indent, format, args);
			break;
		}
	}

	bool IgnoreMessage(LoggerEvent loggerEvent, string format, object[] args) {
		if (loggerEvent != LoggerEvent.Error && loggerEvent != LoggerEvent.Warning)
			return false;
		if (!CanIgnoreMessages)
			return false;
		if (ignoredMessages.ContainsKey(format)) {
			NumIgnoredMessages++;
			return true;
		}

		ignoredMessages[format] = true;
		return false;
	}

	void LogMessage(string indent, string format, params object[] args) {
		if (args == null || args.Length == 0)
			Console.WriteLine("{0}{1}", indent, format);
		else
			Console.WriteLine(indent + format, args);
	}

	public static void Log(LoggerEvent loggerEvent, string format, params object[] args) =>
		Instance.Log(null, loggerEvent, format, args);

	public static void e(string format, params object[] args) => Instance.Log(null, LoggerEvent.Error, format, args);
	public static void w(string format, params object[] args) => Instance.Log(null, LoggerEvent.Warning, format, args);
	public static void n(string format, params object[] args) => Instance.Log(null, LoggerEvent.Info, format, args);
	public static void v(string format, params object[] args) => Instance.Log(null, LoggerEvent.Verbose, format, args);

	public static void vv(string format, params object[] args) =>
		Instance.Log(null, LoggerEvent.VeryVerbose, format, args);
}
