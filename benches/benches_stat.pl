#!/usr/bin/perl
use strict;
use warnings;
use FindBin qw($RealBin);
use Text::CSV_XS qw(csv);

my $file = "$RealBin/benchmark_results.csv";

# Read CSV: rows are arrayrefs of column values
my $rows = csv(
    in       => $file,
    headers  => "auto",   # first row -> keys, each row is a hashref
    encoding => "utf8",
);

# $rows is arrayref of hashrefs: one hash per data row, keys = column names
my $columns = [ keys %{ $rows->[0] } ] if @$rows;  # column names
my $num_rows = scalar @$rows;
my $num_cols = scalar @$columns;

print "Columns ($num_cols): ", join(", ", sort @$columns), "\n";
print "Rows: $num_rows\n\n";

my @ap_dims = qw/Security Department Region/;

# Example: first 3 rows as rows and columns
for my $i (0 .. $#$rows) {
    last if $i >= @$rows;
    my $row = $rows->[$i];
   # print "Row $i:\n";
    for my $col (@$columns) {
      #  print "  $col => ", $row->{$col} // "", "\n";
        if($col eq "user_ap") {
            my $user_ap = $row->{$col};
            my @user_ap_dims = split(/ && /, $user_ap);
            my %user_ap_dim = map { /(.*)::(.*)/  } @user_ap_dims;
            my $new_user_ap = join(" && ", map { $_."::".$user_ap_dim{$_} } grep { exists $user_ap_dim{$_} } @ap_dims);
            my $etsi_user_ap = join(" && ", map {  exists $user_ap_dim{$_}? $_."::".$user_ap_dim{$_} : $_."::*" } @ap_dims);
            $row->{$col} = $new_user_ap;
            $row->{"etsi_user_ap"} = $etsi_user_ap;
           # print "  etsi_user_ap => ", $row->{"etsi_user_ap"} // "", "\n";
        }
    }
    #print "\n";
}

my @columns = qw/enc_ap user_ap type encryption decryption decryption_result/;

my @etsi_columns = qw/etsi_enc_ap etsi_user_ap etsi_type etsi_encryption etsi_decryption etsi_decryption_result/;

my @final_rows = ([@columns, @etsi_columns, "etsi_lp_eq_flag"]);

for my $i (0 .. $#$rows) {
    my $row = $rows->[$i];
    my $user_ap = $row->{"user_ap"};
    my $etsi_user_ap = $row->{"etsi_user_ap"};

my $etsi_row = undef;
my $etsi_lp_eq_flag = 0;
    if($user_ap eq $etsi_user_ap) {
        $etsi_row = $row;
        $etsi_lp_eq_flag = 1;
    }else{
        my @extract_rows = grep { 
            $_->{"enc_ap"} eq $row->{"enc_ap"} &&
            $_->{"type"} eq $row->{"type"} &&
            $_->{"user_ap"} eq $etsi_user_ap } @$rows;
        if(@extract_rows > 0) {
            $etsi_row = $extract_rows[0];
        }else{
            print "Error: no etsi row found for $user_ap and $etsi_user_ap\n";
        }
    }
    if(defined $etsi_row) {
        push @final_rows, [ @{$row}{@columns}, @{$etsi_row}{@columns}, $etsi_lp_eq_flag ];
    }
}

open(my $fh, '>', 'benchmark_results_etsi.csv') or die "Could not open file 'benchmark_results_etsi.csv' $!";

for my $row (@final_rows) {
    print $fh join(",", map {
        # Quote values containing special CSV chars (comma, quote, newline)
        my $val = defined($_) ? $_ : '';
        if ($val =~ /["\,\n]/) {
            $val =~ s/"/""/g;
            "\"$val\"";
        } else {
            $val;
        }
    } @$row), "\n";
}

close $fh;