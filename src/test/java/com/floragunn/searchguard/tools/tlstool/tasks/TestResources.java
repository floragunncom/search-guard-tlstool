/*
 * Copyright 2017-2018 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

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
