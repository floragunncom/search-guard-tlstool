package com.floragunn.searchguard.tools.tlstool;

public class ToolException extends Exception {

	private static final long serialVersionUID = 1722420699098612036L;

	public ToolException() {
		super();
	}

	public ToolException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public ToolException(String message, Throwable cause) {
		super(message, cause);
	}

	public ToolException(String message) {
		super(message);
	}

	public ToolException(Throwable cause) {
		super(cause);
	}

}
