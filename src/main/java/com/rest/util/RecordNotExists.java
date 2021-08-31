package com.rest.util;

public class RecordNotExists extends Exception {
	public String getMessage() {
		return toString();
	}
	
	public String toString() {
		return "Record Not Exists";
	}
}
