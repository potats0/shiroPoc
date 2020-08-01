/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.subject;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.Set;


@SuppressWarnings({"unchecked"})
public class SimplePrincipalCollection implements Serializable {

    private static final long serialVersionUID = -6305224034025797558L;

    //TODO - complete JavaDoc

    private Map<String, Set> realmPrincipals;

    public SimplePrincipalCollection() {
    }


    public int hashCode() {
        if (this.realmPrincipals != null && !realmPrincipals.isEmpty()) {
            return realmPrincipals.hashCode();
        }
        return super.hashCode();
    }


    /**
     * Serialization write support.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this)
     *
     * @param out output stream provided by Java serialization
     * @throws IOException if there is a stream error
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeBoolean(false);
    }

    /**
     * Serialization read support - reads in the Map principals collection if it exists in the
     * input stream.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this)
     *
     * @param in input stream provided by
     * @throws IOException            if there is an input/output problem
     * @throws ClassNotFoundException if the underlying Map implementation class is not available to the classloader.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        boolean principalsExist = in.readBoolean();
        if (principalsExist) {
            this.realmPrincipals = (Map<String, Set>) in.readObject();
        }
    }

}
