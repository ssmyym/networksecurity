# ecc.py
class Point:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if x is not None and y is not None:
            if y ** 2 != x ** 3 + a * x + b:
                raise ValueError('({}, {}) is not on the curve'.format(x, y))
        else:
            if x is not None or y is not None:
                raise ValueError('Both x and y must be None or neither')

    def __eq__(self, other):
        return self.x == other.x and self.y == self.y \
            and self.a == other.a and self.b == other.b

    def __repr__(self):
        if self.x is None:
            return 'Point (intifnity)'
        else:
            return 'Point({}, {})_{}_{}'.format(self.x,self.y,self.a,self.b)

    ## 두 점을 기준으로 두 점이 x 축에 수직인 직선 위에 있는 경우 , 두 점이 x 축에 수직인 직선 위에 있지 않은 경우, 두점이 같은 경우
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {} , {} are not same curve'.format(self,other))

        # A + I = A (I는 무한 원점 == None으로 표현)
        if self.x is None:
            return other
        if other.x is None:
            return self

        # 역원에 대한 덧셈 : 두 점은 x가 같고 y가 다른 경우이며 두 점을 이은 직선은 x추에 수직        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        # x1 != x2 인 경우, 두 점이 다르며 y축에 평행한 경우
        # P1 = (x1,y1), p3(x3,y3) p1+p1 = p3 s = (3x1^2 +a ) /2y1 , x3 = s^2 - 2x1 , y3= s(x1 - x3) - y1
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s ** 2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # x좌표는 같고 y좌표는 다른 경우 x축에 대칭
        if self.x == other.x and self.y != other.y:
            return self.__class__(None,None,self.a,self.b)

        ## 두 점이 같은 경우 접하는 경우 x3 = s^2 - 2x1 y3 = s(x1-x3) - y1
        if self == other:
            s = ((self.x * self.x) + (self.x * self.x) + (self.x * self.x) + self.a) /(self.y +self.y)
            x = s ** 2 - (self.x + self.x)
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        ## 예외처리

        # 두점이 같은 경우 (접하는데 그 점이 y가 0인 경우 - Divied zero)
        if self == other and self.y == 0:
            return self.__class__(None,None,self.a,self.b)

        raise NotImplementedError

    def __rmul__(self, confficient):
        coef = confficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


# field_element.py
class FieldElement:
    def __init__(self,num,prime):
        if num >= prime or num < 0:  # 1
            error = 'Num {} not in field range 0 to {}'.format(
                num, prime - 1
            )
            raise ValueError(error) ## num 값이 0과 prime -1의 사이값인지 조사
        self.num = num
        self.prime = prime

    # 개체 설명
    def __repr__(self):  # 개체 설명용
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    # ==
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    # !=
    def __ne__(self, other):
        return not (self == other)

    ## add 구현
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cammpt add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num,self.prime)

    ## sub 구현
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cammpt sub two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num,self.prime)
    ## mul *
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cammpt multi two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num,self.prime)

    # 페르마의 정리에 따라 p 가 소수이면 모든 정수 a에 대해 a ^p ≡ a (mod p)이다
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        result = pow(self.num, n , self.prime) # python 거듭제곱 모듈러 연산
        return self.__class__(result,self.prime)

    # 나눗셉 연산 모듈러
    # a/b = a * b ^(-1)   b^(p-1) = 1b^(-1) = b^(-1) * 1 = b^(-1) * b^(p-1) = b^(p-2)
    # b^-1 = b^(p-2)
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cammpt dive two numbers in different Fields')
        num = self.num * pow(other.num, other.prime - 2, other.prime) % other.prime
        return self.__class__(num, self.prime)
