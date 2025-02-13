rule Trojan_MSIL_RedLineSteal_NC_2147925581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineSteal.NC!MTB"
        threat_id = "2147925581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TeEnvironmentlegraEnvironmentm DEnvironmentesktoEnvironmentp\\tdEnvironmentata" ascii //weight: 2
        $x_1_2 = "LEnvironmentogiEnvironmentn DatEnvironmenta" ascii //weight: 1
        $x_1_3 = "ApGenericpDaGenericta\\RGenericoamiGenericng" ascii //weight: 1
        $x_1_4 = "BCrUnmanagedTypeyptDecrUnmanagedTypeypt" ascii //weight: 1
        $x_1_5 = "%USERPFile.WriteROFILE%\\AppFile.WriteData\\RoamiFile.Writeng" ascii //weight: 1
        $x_1_6 = "%USERPserviceInterface.ExtensionROFILE%\\ApserviceInterface.ExtensionpData\\LocaserviceInterface.Extensionl" ascii //weight: 1
        $x_1_7 = "Yandex\\YaAddon" ascii //weight: 1
        $x_1_8 = "wallet" ascii //weight: 1
        $x_1_9 = "get_Credentials" ascii //weight: 1
        $x_1_10 = "set_encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

