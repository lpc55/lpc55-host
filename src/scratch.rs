fn hexadecimal_value(input: &str) -> nom::IResult<&str, u16> {
    use nom::{
        combinator::map_res,
        sequence::preceded,
        branch::alt,
        bytes::complete::tag,
        combinator::recognize,
        multi::many1,
        sequence::terminated,
        character::complete::one_of,
        multi::many0,
        character::complete::char,
    };

  map_res(
    preceded(
      alt((tag("0x"), tag("0X"))),
      recognize(
        many1(
          terminated(one_of("0123456789abcdefABCDEF"), many0(char('_')))
        )
      )
    ),
    |out: &str| u16::from_str_radix(&str::replace(&out, "_", ""), 16)
  )(input)
}

