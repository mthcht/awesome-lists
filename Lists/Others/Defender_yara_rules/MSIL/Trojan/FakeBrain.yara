rule Trojan_MSIL_FakeBrain_DA_2147973276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeBrain.DA!MTB"
        threat_id = "2147973276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeBrain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogCreditCardCreate" ascii //weight: 1
        $x_1_2 = "FIND_LOCAL_PAYMENT_CONTEXT" ascii //weight: 1
        $x_1_3 = "{\"merchantId\":\"" ascii //weight: 1
        $x_1_4 = ",\"publicKey\":\"" ascii //weight: 1
        $x_1_5 = ",\"privateKey\":\"" ascii //weight: 1
        $x_1_6 = ",\"timestamp\":\"" ascii //weight: 1
        $x_1_7 = "CREATE_LOCAL_PAYMENT_CONTEXT" ascii //weight: 1
        $x_1_8 = "GENERATE_CUSTOMER_RECOMMENDATIONS_MUTATION" ascii //weight: 1
        $x_1_9 = "CREATE_CUSTOMER_SESSION_MUTATION" ascii //weight: 1
        $x_1_10 = "Braintree .NET" ascii //weight: 1
        $x_1_11 = "Braintree.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FakeBrain_DB_2147973277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeBrain.DB!MTB"
        threat_id = "2147973277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeBrain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoInitializer" ascii //weight: 1
        $x_1_2 = "AnalyzeAndPrint" ascii //weight: 1
        $x_1_3 = "CodebaseAnalysisResult" ascii //weight: 1
        $x_1_4 = "ConfigurationAnalyzer" ascii //weight: 1
        $x_1_5 = "MapToPayload" ascii //weight: 1
        $x_1_6 = "CloudProviderAnalyzer" ascii //weight: 1
        $x_1_7 = "ContainerAnalyzer" ascii //weight: 1
        $x_1_8 = "/var/run/secrets/kubernetes.io/serviceaccount/token" ascii //weight: 1
        $x_1_9 = "AWS_" ascii //weight: 1
        $x_1_10 = "AZURE_" ascii //weight: 1
        $x_1_11 = "GOOGLE_" ascii //weight: 1
        $x_1_12 = "ASPNETCORE_" ascii //weight: 1
        $x_1_13 = "ASPNET_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

