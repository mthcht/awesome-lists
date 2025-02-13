rule PWS_MSIL_Infostealer_PAC_2147776893_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Infostealer.PAC!MTB"
        threat_id = "2147776893"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "endpointConfigurationName" ascii //weight: 1
        $x_1_2 = "GetAllNetworkInterfaces" ascii //weight: 1
        $x_1_3 = "localhost.IUserServiceu" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 79 41 63 74 69 6f 6e [0-2] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_5 = "GetPhysicalAddress" ascii //weight: 1
        $x_1_6 = "ConfigurationName" ascii //weight: 1
        $x_1_7 = "set_ProxyAddress" ascii //weight: 1
        $x_1_8 = "BasicHttpBinding" ascii //weight: 1
        $x_1_9 = "Client.localhost" ascii //weight: 1
        $x_1_10 = "EndpointAddress" ascii //weight: 1
        $x_1_11 = "Action(http://" ascii //weight: 1
        $x_1_12 = "remoteAddress" ascii //weight: 1
        $x_1_13 = "System.Xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_MSIL_Infostealer_PAE_2147778065_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Infostealer.PAE!MTB"
        threat_id = "2147778065"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WE ARE THE KU KLUX KLAN.. WE HATE NIGGERS.. WE HATE FAGGOTS.. AND WE HATE JEWS" wide //weight: 1
        $x_1_2 = "HAPPY SAINT TARRANTS DAY FUCKERS" wide //weight: 1
        $x_1_3 = "HAVE FUN ANALYZING FUCKERS!!!" wide //weight: 1
        $x_1_4 = "georgie floyd" wide //weight: 1
        $x_1_5 = "discordcanary" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

