(ns build
  (:require [clojure.tools.build.api :as b]))

(def lib 'ieugen/nebula-cert-clj)
(def version (format "0.1.%s" (b/git-count-revs nil)))
(def class-dir "target/generated/classes")
(def jar-file (format "target/lib/%s-%s.jar" (name lib) version))

;; delay to defer side effects (artifact downloads)
(def basis (delay (b/create-basis {:project "deps.edn"})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn compile-java [_]
  (b/javac {:src-dirs ["generated/java"]
            :class-dir class-dir
            :basis @basis
            :javac-opts ["-proc:none" "--release" "11"]}))

(defn jar [_]
  (compile nil)
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]})
  (b/copy-dir {:src-dirs ["src/clj" "src/resources"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file}))