#!/bin/bash -xe
cmd=./natest

echo "Single match and wildcard"
  $cmd 'a=1' 'a=1'
  $cmd '(a=1)' 'a=1'
  $cmd 'a=*' 'a=1'
  $cmd 'a=*' 'a=2'
! $cmd 'a=1' 'a=2'
! $cmd 'a=1' 'b=1'
! $cmd 'a=*' 'b=1'

echo "Single OR"
  $cmd 'a=1 or b=1' 'a=1'
  $cmd 'a=1 or b=1' 'b=1'
  $cmd '(a=1 or b=1)' 'a=1'
  $cmd '(a=1) or (b=1)' 'b=1'
! $cmd 'a=1 or b=1' 'c=1'
! $cmd 'a=1 or b=1' 'b=2'

echo "Hex string byte comparison"
  $cmd 'a=1 or b=[414243]' 'b=ABC'
! $cmd 'a=1 or b=[414243]' 'b=ABZ'
! $cmd 'a=1 or b=[41424]' 'b=ABC'

echo "Multiple OR"
  $cmd 'a=1 or b=1 or b=2' 'a=1'
  $cmd 'a=1 or b=1 or b=2' 'b=1'
  $cmd 'a=1 or b=1 or b=2' 'b=2'
! $cmd 'a=1 or b=1 or b=2' 'a=2' 'b=3'

echo "Single AND and wildcard"
  $cmd 'a=1 and b=1' 'a=1' 'b=1'
  $cmd 'a=1 and b=*' 'a=1' 'b=1'
  $cmd 'a=1 and b=*' 'a=1' 'b=2'
! $cmd 'a=1 and b=1' 'a=1'
! $cmd 'a=1 and b=1' 'b=1'

echo "Multiple AND with some arbitrary nesting"
  $cmd 'a=1 and b=1 and c=1' 'a=1' 'b=1' 'c=1'
  $cmd '(a=1 and (b=1 and c=1))' 'a=1' 'b=1' 'c=1'
! $cmd 'a=1 and b=1 and c=1' 'b=1' 'c=1'

echo "Combinations"
  $cmd 'a=1 and b=1 or b=2' 'a=1' 'b=1'
  $cmd 'a=1 and b=1 or b=2' 'a=1' 'b=2'
  $cmd '(a=1 and b=1) or b=2' 'b=2'
  $cmd '(a=1 and b=1) or b=2' 'a=1' 'b=1'
! $cmd 'a=1 and b=1 or b=2' 'b=2'
! $cmd 'a=1 and b=1 or b=2' 'a=1' 'b=3'
! $cmd '(a=1 and b=1) or b=2' 'b=1'
! $cmd '(a=1 and b=1) or b=2' 'a=2' 'b=1'

  $cmd 'a=1 or b=1 and c=1' 'a=1'
  $cmd 'a=1 or (b=1 and c=1)' 'a=1'
  $cmd 'a=1 or b=1 and c=1' 'b=1' 'c=1'
  $cmd 'a=1 or (b=1 and c=1)' 'b=1' 'c=1'
! $cmd 'a=1 or b=1 and c=1' 'a=2' 'b=1' 'c=2'
! $cmd 'a=1 or b=1 and c=1' 'b=1' 'c=2'

  $cmd '(a=1 or b=1) and c=1' 'a=1' 'c=1'
  $cmd '(a=1 or b=1) and c=1' 'b=1' 'c=1'
! $cmd '(a=1 or b=1) and c=1' 'a=1'
! $cmd '(a=1 or b=1) and c=1' 'b=1'
! $cmd '(a=1 or b=1) and c=1' 'c=1'

  $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=1' 'b=1'
  $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=2' 'b=1'
  $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=1' 'b=2' 'c=1'
  $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=2' 'b=2' 'c=1'
! $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=2' 'b=3' 'c=1'
! $cmd '((a=1 or a=2) and (b=1 or (b=2 and c=1)))' 'a=2' 'b=2' 'c=2'

echo "Parse errors"
! $cmd '(a=)' 'a=1'
! $cmd '(a=1 b=1)' 'a=1'
! $cmd '((a=1 or b=1)' 'a=1'
! $cmd 'a=1 or' 'a=1'
! $cmd 'a or b' 'a=1'
! $cmd '((a=1)or b=1)' 'a=1'
