# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Convert-ASN1-X509.t'

use Test::More tests => 39;
BEGIN { use_ok('Crypt::X509') };

$cert=loadcert('t/verisign.der');

is (length $cert, 774,'certificate file loaded');

$decoded = Crypt::X509->new( cert => $cert);

ok( defined $decoded,'new() returned something' );

ok( $decoded->isa('Crypt::X509'), 'and it\'s the right class' );

is ( $decoded->error,undef, 'decode successful');

is ($decoded->not_after,1848787199, 'not_after got parsed');

is (join(',',@{$decoded->Issuer}),join(',',@{$decoded->Subject}), 'Root CA: Subject equals Issuer');

$cert=loadcert('t/aj.cer');
$decoded2 = Crypt::X509->new( cert => $cert);
is ( $decoded2->error,undef, 'decode successful');
is ( join(':',@{$decoded2->KeyUsage}), "digitalSignature:keyEncipherment:dataEncipherment", 'Keyusagecheck' );
# this has also to work twice
is ( join(':',@{$decoded2->KeyUsage}), "digitalSignature:keyEncipherment:dataEncipherment", 'Keyusagecheck again' );

is (join(',',@{$decoded2->Subject}),"E=alexander.jung\@allianz.de,C=DE,O=Allianz Group,CN=Alexander Jung", 'Subject parsed');

is ($decoded2->subject_country, "DE", "Subject_country");
is ($decoded2->subject_state, undef, "Subject_state");
is ($decoded2->subject_org, "Allianz Group", "Subject_org");
is ($decoded2->subject_ou, undef, "Subject_ou");
is ($decoded2->subject_email, "alexander.jung\@allianz.de", "Subject_email");

is (join(',',@{$decoded2->Issuer}),"C=DE,O=Allianz Group,CN=Allianz Dresdner CA","Issuer Parsed");

is ($decoded2->issuer_cn, "Allianz Dresdner CA", "Issuer_cn");
is ($decoded2->issuer_country,"DE","Isssuer_country");
is ($decoded2->issuer_state,undef,"Issuer_state");
is ($decoded2->issuer_locality,undef,"Issuer_locality");
is ($decoded2->issuer_org,"Allianz Group","Issuer_org");
is ($decoded2->issuer_email,undef,"Issuer_email");

is ($decoded2->pubkey_algorithm,"1.2.840.113549.1.1.1","pubkey_algorithm");
is ($decoded2->sig_algorithm,"1.2.840.113549.1.1.5","sig_algorithm");
is (length($decoded2->pubkey),140,"Pubkey length");
is (length($decoded2->signature),256,"Signature Length");


is (join(',',@{$decoded2->SubjectAltName}),"alexander.jung\@allianz.de",'SubjectAltName parsed');

$cert=loadcert('t/aj2.cer');
$decoded3 = Crypt::X509->new( cert => $cert);
is ( $decoded3->error,undef, 'decode successful');
is ( join(':',@{$decoded3->KeyUsage}),"digitalSignature:keyAgreement", 'KeyUsage Check AuthCert' );

$cert=loadcert('t/allianz_root.cer');
$decoded = Crypt::X509->new( cert => $cert);
is ( $decoded->error,undef, 'decode successful');

is (join(',',@{$decoded->authorityCertIssuer}),"C=DE,O=Allianz Group,CN=Allianz Group Root CA","authorityCertIssuer");
is ($decoded->CRLDistributionPoints->[0],"http://rootca.allianz.com/rootca.crl","CRLDistributionPoints");

is ($decoded->authority_cn, "Allianz Group Root CA", "authority_cn");
is ($decoded->authority_country,"DE","authority_country");
is ($decoded->authority_state,undef,"authority_state");
is ($decoded->authority_locality,undef,"authority_locality");
is ($decoded->authority_org,"Allianz Group","authority_org");
is ($decoded->authority_email,undef,"authority_email");


sub loadcert {
	my $file =shift;
	open FILE , $file || die "cannot load test certificate" . $file . "\n";
		binmode FILE; # HELLO Windows, dont fuss with this
		my $holdTerminator = $/;
		undef $/; # using slurp mode to read the DER-encoded binary certificate
		my $cert = <FILE>;
		$/ = $holdTerminator;
	close FILE;
	return $cert;
}