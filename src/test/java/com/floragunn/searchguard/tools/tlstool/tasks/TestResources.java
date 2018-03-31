package com.floragunn.searchguard.tools.tlstool.tasks;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

class TestResources {
	static String getAbsolutePath(String resourceNameInClassPath) {
		try {
			URL url = TestResources.class.getClassLoader().getResource(resourceNameInClassPath);
			
			if (url == null) {
				throw new RuntimeException("Could not find " + resourceNameInClassPath + " in class path");
			}
			
			return Paths.get(url.toURI()).toFile().getAbsolutePath();
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
}
