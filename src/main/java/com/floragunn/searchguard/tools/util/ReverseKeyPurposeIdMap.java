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

package com.floragunn.searchguard.tools.util;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class ReverseKeyPurposeIdMap {
	private static final Logger log = LogManager.getLogger(ReverseKeyPurposeIdMap.class);

	private static Map<String, String> map;

	static {
		try {
			map = createMap();
		} catch (Exception e) {
			log.warn("Error while initializing ReverseKeyPurposeIdMap", e);
		}
	}

	public static String getNameById(String id) {
		if (map == null) {
			return id;
		}

		String value = map.get(id);

		if (value != null) {
			return value;
		} else {
			return id;
		}
	}

	public static List<String> getNamesById(List<String> ids) {
		if (ids == null) {
			return null;
		}

		List<String> result = new ArrayList<>(ids.size());

		for (String id : ids) {
			result.add(getNameById(id));
		}

		return result;
	}

	private static Map<String, String> createMap()
			throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException {
		Map<String, String> result = new HashMap<>();

		Field[] fields = KeyPurposeId.class.getDeclaredFields();
		for (Field field : fields) {
			if ((field.getModifiers() & (Modifier.PUBLIC | Modifier.STATIC)) == (Modifier.PUBLIC | Modifier.STATIC)
					&& field.getType().isAssignableFrom(KeyPurposeId.class)) {
				result.put(((KeyPurposeId) KeyPurposeId.class.getField(field.getName()).get(null)).getId(),
						field.getName());
			}
		}

		return result;
	}
}
