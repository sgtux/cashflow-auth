package com.cashflow.auth.architecture;

import org.springframework.boot.test.context.SpringBootTest;

import com.cashflow.auth.adapter.in.controller.JwksController;
import com.cashflow.auth.adapter.out.token.SigningKeys;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;;

// DoNotIncludeTests: sem isso, o proprio LayeredArchitectureTest (e qualquer outra classe de
// teste sob com.cashflow.auth) entra na analise. Como ele importa JwksController/SigningKeys
// para o ignoreDependency abaixo, essa importacao virava "violacao" da propria regra que ele
// declara - o teste acusava a si mesmo.
@AnalyzeClasses(packages = "com.cashflow.auth", importOptions = ImportOption.DoNotIncludeTests.class)
@SpringBootTest
public class LayeredArchitectureTest {

    @ArchTest
    public static final ArchRule layered_architecture_test = layeredArchitecture()
            .consideringAllDependencies()
            .layer("AdaptersIn").definedBy("..adapter.in..")
            .layer("AdaptersOut").definedBy("..adapter.out..")
            .layer("PortsIn").definedBy("..application.port.in..")
            .layer("PortsOut").definedBy("..application.port.out..")
            .layer("Config").definedBy("..config..")
            .whereLayer("AdaptersIn").mayOnlyBeAccessedByLayers("Config", "AdaptersIn")
            .whereLayer("AdaptersOut").mayNotBeAccessedByAnyLayer()
            .ignoreDependency(JwksController.class, SigningKeys.class);

    // @ArchTest
    // public static final ArchRule layered_architecture_test = layeredArchitecture()
    //         .consideringAllDependencies()
    //         .layer("AdaptersIn").definedBy("..adapters.in..")
    //         .layer("AdaptersOut").definedBy("..adapters.out..")
    //         .layer("UseCase").definedBy("..application.core.usecase..")
    //         .layer("PortsIn").definedBy("..application.ports.in..")
    //         .layer("PortsOut").definedBy("..application.ports.out..")
    //         .layer("Config").definedBy("..config..")
    //         .whereLayer("AdaptersIn").mayOnlyBeAccessedByLayers("Config")
    //         .whereLayer("AdaptersIn").mayOnlyBeAccessedByLayers("Config")
    //         .whereLayer("UseCase").mayOnlyBeAccessedByLayers("Config")
    //         .whereLayer("PortsIn").mayOnlyBeAccessedByLayers("UseCase", "AdaptersIn")
    //         .whereLayer("PortsOut").mayOnlyBeAccessedByLayers("UseCase", "AdaptersOut")
    //         .whereLayer("Config").mayNotBeAccessedByAnyLayer();
}
