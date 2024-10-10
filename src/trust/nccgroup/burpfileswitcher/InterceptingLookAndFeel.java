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

import org.fife.ui.rtextarea.RTextAreaBase;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import net.sf.cglib.proxy.*;

class InterceptingLookAndFeel {

  final private static Map<Class<?>, LookAndFeel> proxymap = new HashMap<>();

  static LookAndFeel getInstance(LookAndFeel original) {
    LookAndFeel proxy = proxymap.getOrDefault(original.getClass(), null);
    if (proxy != null) {
      return proxy;
    }
    proxy = setupProxy(original);
    proxymap.put(original.getClass(), proxy);
    return proxy;
  }

//  private static LookAndFeel setupProxy(LookAndFeel original) {
//    LookAndFeel proxylaf = (LookAndFeel) Proxy.newProxyInstance(
//      original.getClass().getClassLoader(),
//      original.getClass().getInterfaces(),
//      new InvocationHandler() {
//        @Override
//        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
//          if ("provideErrorFeedback".equals(method.getName())) {
//            if (args.length == 1) {
//              Object o = args[0];
//              if (o instanceof Component) {
//                Component c = (Component)o;
//                if (c instanceof RTextAreaBase || c instanceof RTextScrollPane) {
//                  return null;
//                }
//
//              }
//            }
//          }
//          return method.invoke(proxy, args);
//        }
//      }
//    );
//    return proxylaf;
//  }


  private static LookAndFeel setupProxy(LookAndFeel original) {
    if (original.getClass().getName().contains("EnhancerByCGLIB")) {
      return original;
    }
    try {
      Enhancer e = new Enhancer();
      e.setSuperclass(original.getClass());
      e.setCallback(new MethodInterceptor() {
        public Object intercept(Object obj, Method method,
                                Object[] args, MethodProxy p) throws Throwable {

          if ("provideErrorFeedback".equals(method.getName())) {
            Class<?>[] pts = method.getParameterTypes();
            if (pts.length == 1 && Component.class.equals(pts[0])) {
              Object o = args[0];
              if (o instanceof Component) {
                Component c = (Component) o;
                if (c instanceof RTextAreaBase || c instanceof RTextScrollPane) {
                  //System.out.println(c.getClass().getName());
                  return null;
                }
              }
            }
          }
          return p.invokeSuper(obj, args);
        }
      });
      return (LookAndFeel) e.create();
    } catch (Throwable t) {
      t.printStackTrace();
      return original;
    }
  }
}

