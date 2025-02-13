rule Backdoor_Linux_Fegrat_B_2147770260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Fegrat.B!dha"
        threat_id = "2147770260"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Fegrat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedFlare/rat/modules/socks.(*HTTPProxyClient).handshake" ascii //weight: 1
        $x_1_2 = "RedFlare/rat/platforms/linux/dyloader.(*memoryLoader).ExecutePluginFunction.func1.1" ascii //weight: 1
        $x_1_3 = "RedFlare/rat.Core.Destroy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

