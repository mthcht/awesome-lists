rule Trojan_PyPI_LiteLlmSupplyChain_D_2147980931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PyPI/LiteLlmSupplyChain.D"
        threat_id = "2147980931"
        type = "Trojan"
        platform = "PyPI: "
        family = "LiteLlmSupplyChain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " -c " wide //weight: 1
        $x_1_2 = "prisma.prisma(" wide //weight: 1
        $x_1_3 = "credential_values" wide //weight: 1
        $x_1_4 = "litellm_credentialstable" wide //weight: 1
        $x_1_5 = "litellm_proxymodeltable" wide //weight: 1
        $x_1_6 = "limit 500" wide //weight: 1
        $x_1_7 = "json.dumps(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

