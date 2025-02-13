rule PWS_MSIL_Evital_A_2147725698_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Evital.A!bit"
        threat_id = "2147725698"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evital"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Evrial.Stealer" ascii //weight: 1
        $x_1_2 = "Evrial.Hardware" ascii //weight: 1
        $x_1_3 = "Evrial.Cookies" ascii //weight: 1
        $x_1_4 = "https://projectevrial.ru/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Evital_B_2147734643_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Evital.B!bit"
        threat_id = "2147734643"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evital"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "hwid={0}&os={1}&file={2}&cookie={3}&pswd={4}&credit={5}&autofill={6}&wallets={7}&id={8}&version={9}" wide //weight: 3
        $x_3_2 = "whoiam.space/gate.php" wide //weight: 3
        $x_3_3 = "hostname|encryptedPassword|encryptedUsername" wide //weight: 3
        $x_3_4 = "screen.jpeg" wide //weight: 3
        $x_2_5 = "purple\\accounts.xml" wide //weight: 2
        $x_2_6 = "Exodus\\exodus.wallet" wide //weight: 2
        $x_2_7 = "recentservers.xml" wide //weight: 2
        $x_2_8 = "sitemanager.xml" wide //weight: 2
        $x_1_9 = "select * from Win32_VideoController" wide //weight: 1
        $x_1_10 = "select * from Win32_Processor" wide //weight: 1
        $x_1_11 = "select * from Win32_DiskDrive" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

