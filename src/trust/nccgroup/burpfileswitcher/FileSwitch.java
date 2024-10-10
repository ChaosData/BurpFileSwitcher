/*
Copyright 2018-2022 NCC Group

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package trust.nccgroup.burpfileswitcher;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class FileSwitch {

  public boolean isEnabled;
  private String uri;
  private transient String uri_key;
  private String data;
  private transient byte[] raw_data;
  public String remote_uri;
  public String comment;

  public FileSwitch(String _uri, String _remote_uri, String _comment) {
    isEnabled = true;
    uri = _uri;
    uri_key = FileManager.getKey(uri);
    data = "";
    raw_data = data.getBytes(StandardCharsets.UTF_8);
    remote_uri = _remote_uri;
    comment = _comment;
  }

  public void setUri(String _uri) {
    uri = _uri;
    uri_key = FileManager.getKey(uri);
  }

  public String getUri() {
    return uri;
  }

  public String getUriKey() {
    return uri_key;
  }

  public void setData(String _data) {
    data = _data;
    raw_data = data.getBytes(StandardCharsets.UTF_8);
  }

  public String getData() {
    return data;
  }

  public byte[] getRawData() {
    return raw_data;
  }

}
