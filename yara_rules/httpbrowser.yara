rule HttpBrowser
{
    meta:
        author = "kev"
        description = "HttpBrowser C2 connect function"
        cape_type = "HttpBrowser Payload"
    strings:
        $connect_1 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_2 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? 8D ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_3 = {68 40 1F 00 00 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? BB ?? ?? ?? ?? 53 FF D6 59 50 BF ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 59 59}
        $connect_4 = {33 C0 57 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 6A 01 FF 75 08 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $connect_1 or $connect_2 or $connect_3 or $connect_4
}
