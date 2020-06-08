import math

class Time:
    def __init__(self, strHour, strMinute, strSecond, strMillisecond):
        self.__hour = int(strHour)
        self.__minute = int(strMinute)
        self.__second = int(strSecond)
        self.__millisecond = float(f"0.{strMillisecond}")

    def diffTime(self, otherTime):
        return abs(self.toSeconds() - otherTime.toSeconds())

    def toSeconds(self):
        return self.__hour*3600 + self.__minute*60 + self.__second + self.__millisecond

    def fromSeconds(seconds):
        return Time(math.floor(seconds/3600%60),
                math.floor(seconds/60%60),
                math.floor(seconds%60),
                float(seconds-int(seconds)))
