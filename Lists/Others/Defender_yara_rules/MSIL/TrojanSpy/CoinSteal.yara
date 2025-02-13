rule TrojanSpy_MSIL_CoinSteal_A_2147724823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.A!bit"
        threat_id = "2147724823"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bytecoinwallet.wallet" wide //weight: 1
        $x_1_2 = "CryptoService.pdb" ascii //weight: 1
        $x_1_3 = "dsciuyizhiuuc.php?type=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_CoinSteal_B_2147724890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.B!bit"
        threat_id = "2147724890"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VictimLogs" ascii //weight: 1
        $x_1_2 = "BitcoinWallet" ascii //weight: 1
        $x_1_3 = "SendUrlAndExecute" ascii //weight: 1
        $x_1_4 = "get_Screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_CoinSteal_E_2147725451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.E!bit"
        threat_id = "2147725451"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bitcoin-Qt" wide //weight: 1
        $x_1_2 = "wallet.dat" wide //weight: 1
        $x_1_3 = "\\stealer.exe" wide //weight: 1
        $x_1_4 = "shuffler.php?type={0}&user={1}&copy={2}" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_CoinSteal_F_2147726559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.F!bit"
        threat_id = "2147726559"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1JDtpK8sLG8GUFFPyd56WrEfMTxU9SFDwQ" wide //weight: 1
        $x_1_2 = "0xd6de32d78a6656c1c3da2e880e9b0ce024b2b272" wide //weight: 1
        $x_1_3 = "LYbg4ryEiAzzFPy1tFpSkHsHaT8mEvaUPr" wide //weight: 1
        $x_1_4 = "isValidLTCAddress" ascii //weight: 1
        $x_1_5 = "IsValidETHAddress" ascii //weight: 1
        $x_1_6 = "IsValidBitcoinAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_CoinSteal_G_2147728119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.G!bit"
        threat_id = "2147728119"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 2
        $x_2_2 = "api.opennicproject.org/geoip" wide //weight: 2
        $x_2_3 = "svcVersion" wide //weight: 2
        $x_1_4 = ".vshost.exe" wide //weight: 1
        $x_1_5 = "}{_+$*!#%^)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_CoinSteal_H_2147730058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.H!bit"
        threat_id = "2147730058"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1GGrzXqMPFHepXArb6b6Kfs4yH6GEtvicY" wide //weight: 2
        $x_1_2 = "vanderbilt" wide //weight: 1
        $x_1_3 = "Bitcoin Wallet" wide //weight: 1
        $x_1_4 = "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_CoinSteal_I_2147730673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinSteal.I!bit"
        threat_id = "2147730673"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "15aHEE5BmAw3KZ59ieurbj8qDemqT7ytG9" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "^(1|3)[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz].*$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

