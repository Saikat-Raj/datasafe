package de.adorsys.datasafe.runtimedelegate;

import com.squareup.javapoet.*;

import javax.annotation.Generated;
import javax.annotation.Nullable;
import javax.annotation.processing.Filer;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import java.io.IOError;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

class RuntimeDelegateGenerator {

    private static final String CAPTOR_TYPE_NAME = "ArgumentsCaptor";
    private static final String CAPTOR_NAME = "argumentsCaptor";
    private static final String DELEGATE_NAME = "delegate";

    void generate(TypeElement forClass,
                  Class contextClass,
                  ExecutableElement usingConstructor,
                  Set<Class> addAnnotations,
                  Filer filer) {
        TypeSpec.Builder delegator = TypeSpec
            .classBuilder(forClass.getSimpleName().toString() + "RuntimeDelegatable")
            .addModifiers(Modifier.PUBLIC);


        delegator.addAnnotation(AnnotationSpec
                .builder(Generated.class)
                .addMember("value", CodeBlock.of("$S", RuntimeDelegateGenerator.class.getCanonicalName()))
                .build()
        );

        delegator.addType(addArgsCaptor(usingConstructor));

        delegator.superclass(TypeName.get(forClass.asType()));
        FieldSpec delegate = FieldSpec
                .builder(TypeName.get(forClass.asType()), DELEGATE_NAME, Modifier.PRIVATE, Modifier.FINAL)
                .build();

        if (!forClass.getTypeParameters().isEmpty()) {
            forClass.getTypeParameters().forEach(it -> delegator.addTypeVariable(TypeVariableName.get(it)));
        }

        delegator.addField(delegate);
        addDelegations(delegator, forClass);

        delegator.addMethod(constructor(forClass, contextClass, usingConstructor, addAnnotations));

        JavaFile javaFile = JavaFile
            .builder(ClassName.get(forClass).packageName(), delegator.build())
            .indent("    ")
            .build();

        try {
            javaFile.writeTo(filer);
        } catch (IOException ex) {
            throw new IOError(ex);
        }
    }

    private void addDelegations(TypeSpec.Builder toClass, TypeElement baseClass) {
        baseClass.getEnclosedElements().stream()
            .filter(it -> it instanceof ExecutableElement)
            .filter(it -> it.getKind() == ElementKind.METHOD)
            .filter(it -> !it.getModifiers().contains(Modifier.PRIVATE))
            .forEach(it -> {
                MethodSpec overriddenBase = MethodSpec.overriding((ExecutableElement) it).build();
                MethodSpec.Builder overridden = MethodSpec.overriding((ExecutableElement) it);
                overridden.addCode(
                    delegatingStatement(overriddenBase)
                ).build();

                toClass.addMethod(overridden.build());
            });
    }

    private CodeBlock delegatingStatement(MethodSpec target) {
        String params = target.parameters.stream().map(it -> it.name).collect(Collectors.joining(", "));
        String returnStatementIfNeeded = TypeName.VOID.equals(target.returnType) ? "" : "return ";

        return CodeBlock.builder()
                .beginControlFlow("if (null == " + DELEGATE_NAME + ")")
                .addStatement(returnStatementIfNeeded + "super.$N(" + params + ")", target)
                .nextControlFlow("else")
                .addStatement(returnStatementIfNeeded + DELEGATE_NAME + ".$N(" + params + ")", target)
                .endControlFlow()
            .build();
    }

    private TypeSpec addArgsCaptor(ExecutableElement usingConstructor) {
        TypeSpec.Builder builder = TypeSpec.classBuilder(CAPTOR_TYPE_NAME).addModifiers(Modifier.PUBLIC);
        MethodSpec.Builder ctor = MethodSpec
            .constructorBuilder()
            .addModifiers(Modifier.PRIVATE);

        usingConstructor.getParameters().forEach(it -> {
            FieldSpec argCaptor = FieldSpec.builder(
                TypeName.get(it.asType()),
                firstCharToLowerCase(it.getSimpleName().toString()),
                Modifier.PRIVATE,
                Modifier.FINAL
            ).build();

            ctor.addParameter(argCaptor.type, argCaptor.name);
            ctor.addStatement("this.$N = $N", argCaptor.name, argCaptor.name);

            builder.addField(argCaptor);
            builder.addMethod(MethodSpec.methodBuilder("get" + firstCharToUpperCase(argCaptor.name))
                .addModifiers(Modifier.PUBLIC)
                .returns(argCaptor.type)
                .addCode(CodeBlock.builder().addStatement("return $N", argCaptor).build())
                .build()
            );
        });

        return builder.addMethod(ctor.build()).build();
    }

    private MethodSpec constructor(TypeElement forClass, Class contextClass,
                                   ExecutableElement usingConstructor, Set<Class> addAnnotations) {
        MethodSpec.Builder method = MethodSpec.constructorBuilder().addModifiers(Modifier.PUBLIC);
        ParameterSpec contextParam = ParameterSpec.builder(
                ClassName.get(contextClass),
                "context"
        ).addAnnotation(Nullable.class).build();

        method.addParameter(contextParam);

        usingConstructor.getParameters().forEach(it ->
            method.addParameter(
                TypeName.get(it.asType()),
                firstCharToLowerCase(it.getSimpleName().toString())
            )
            .addAnnotations(
                it.getAnnotationMirrors().stream().map(AnnotationSpec::get).collect(Collectors.toList())
            )
        );

        addAnnotations.forEach(method::addAnnotation);

        CodeBlock.Builder block = CodeBlock.builder();

        block.addStatement("super(" + computeOriginalCtorArgs(usingConstructor) + ")");
        addCaptor(block, usingConstructor);

        block.addStatement(
                DELEGATE_NAME + " = $N != null ? $N.findOverride($T.class, " + CAPTOR_NAME + ") : null",
                contextParam,
                contextParam,
                forClass.getTypeParameters().isEmpty() ? forClass : ClassName.get(forClass)
        );

        method.addCode(block.build());

        return method.build();
    }

    private void addCaptor(CodeBlock.Builder block, ExecutableElement usingConstructor) {
        block.addStatement(String.format(
                "%s %s = new %s(%s)",
                CAPTOR_TYPE_NAME,
                CAPTOR_NAME,
                CAPTOR_TYPE_NAME,
                computeOriginalCtorArgs(usingConstructor))
        );
    }

    private String computeOriginalCtorArgs(ExecutableElement usingConstructor) {
        return usingConstructor.getParameters().stream()
                .map(it -> firstCharToLowerCase(it.getSimpleName().toString()))
                .collect(Collectors.joining(", "));
    }

    private static String firstCharToLowerCase(String str) {
        char[] asChars = str.toCharArray();
        asChars[0] = Character.toLowerCase(asChars[0]);

        return new String(asChars);
    }

    private static String firstCharToUpperCase(String str) {
        char[] asChars = str.toCharArray();
        asChars[0] = Character.toUpperCase(asChars[0]);

        return new String(asChars);
    }
}
