rule Trojan_Win32_CloudTokenHarvest_ZK_2147967877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CloudTokenHarvest.ZK!MTB"
        threat_id = "2147967877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CloudTokenHarvest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gh auth token" wide //weight: 1
        $x_1_2 = "gcloud config config-helper --format json" wide //weight: 1
        $x_1_3 = "az account get-access-token --output json --resource" wide //weight: 1
        $x_1_4 = "azd auth token --output json --no-prompt --scope" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

