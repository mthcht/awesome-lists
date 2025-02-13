rule Trojan_MSIL_DataStealer_MK_2147758522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DataStealer.MK!MSR"
        threat_id = "2147758522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DataStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://u2729.mh0.ru/" ascii //weight: 5
        $x_1_2 = "browserPasswords" ascii //weight: 1
        $x_1_3 = "Passwords.txt" ascii //weight: 1
        $x_1_4 = "FireFox\\logins.json" ascii //weight: 1
        $x_1_5 = "CreditCards.txt" ascii //weight: 1
        $x_1_6 = "Filezilla\\Passwords.txt" ascii //weight: 1
        $x_1_7 = "VPN\\ProtonVPN\\Passwords.txt" ascii //weight: 1
        $x_1_8 = "Psi\\Passwords.txt" ascii //weight: 1
        $x_1_9 = "Pidgin\\Passwords.txt" ascii //weight: 1
        $x_1_10 = "BitcoinCore\\wallet.dat" ascii //weight: 1
        $x_1_11 = "DashCore\\wallet.dat" ascii //weight: 1
        $x_1_12 = "LitecoinCore\\wallet.dat" ascii //weight: 1
        $x_1_13 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_14 = "SELECT * FROM Win32_BIOS" ascii //weight: 1
        $x_1_15 = "Select * from Win32_ComputerSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

