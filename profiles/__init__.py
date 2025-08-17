"""
Traffic profiles package
"""

from .base import BaseProfile
from .netflix import NetflixProfile  
from .zoom import ZoomProfile
from .fortnite import FortniteProfile

__all__ = ['BaseProfile', 'NetflixProfile', 'ZoomProfile', 'FortniteProfile']
